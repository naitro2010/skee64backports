#pragma warning(disable : 4100 4189 4244)
#include "GameEventHandler.h"
#include "RE/N/NiSmartPointer.h"
#include "REL/Relocation.h"
#include "SKSE/API.h"
#include "SKSE/Interfaces.h"
#include "Hooks.h"
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <xbyak/xbyak.h>
#include "detours/detours.h"
#include "Morpher.h"
namespace plugin {
#undef GetObject
    static uint64_t NIOVTaskUpdateSkinPartitionvtable = 0x0;
    static uint32_t multi_morph_tasks_scheduled = 0;
    static std::recursive_mutex queued_morphs_mutex;
    static void WalkRecalculateNormals(RE::NiNode *node) {
        if (node == nullptr) {
            return;
        }
        for (RE::NiPointer<RE::NiAVObject> obj: node->GetChildren()) {
            if (obj == nullptr) {
                continue;
            }
            if (auto c_node = obj->AsNode()) {
                WalkRecalculateNormals(c_node);
            }
            if (auto geo = obj->AsGeometry()) {
                if (geo->GetGeometryRuntimeData().skinInstance == nullptr) {
                    continue;
                }
                if (geo->GetGeometryRuntimeData().skinInstance->skinPartition == nullptr) {
                    continue;
                }
                if ((!geo->GetGeometryRuntimeData().vertexDesc.HasFlag(RE::BSGraphics::Vertex::VF_NORMAL)) &&
                    (!geo->GetGeometryRuntimeData().vertexDesc.HasFlag(RE::BSGraphics::Vertex::VF_TANGENT))) {
                    continue;
                }
                if (!geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect] ||
                    !geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect]->GetRTTI()->IsKindOf(
                        (RE::NiRTTI *) RE::BSLightingShaderProperty::Ni_RTTI.address())) {
                    continue;
                }
                RE::BSLightingShaderProperty *property =
                    (RE::BSLightingShaderProperty *) geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect].get();
                auto material = property->material;
                if (!material) {
                    continue;
                }
                RE::NiPointer<RE::NiObject> newPartition = nullptr;
                geo->GetGeometryRuntimeData().skinInstance->skinPartition->CreateDeepCopy(newPartition);
                if (!newPartition) {
                    continue;
                }
                RE::NiPointer<RE::NiSkinPartition> newSkinPartition =
                    RE::NiPointer<RE::NiSkinPartition>((RE::NiSkinPartition *) newPartition.get());
                if (newSkinPartition->partitions.size() == 0) {
                    newSkinPartition->DecRefCount();
                    continue;
                }
                {
                    NormalApplicatorBackported applicator(RE::NiPointer<RE::BSGeometry>((RE::BSGeometry *) geo), newSkinPartition);
                    applicator.Apply();
                }
                for (uint32_t p = 1; p < newSkinPartition->partitions.size(); ++p) {
                    auto &pPartition = newSkinPartition->partitions[p];
                    memcpy(pPartition.buffData->rawVertexData, newSkinPartition->partitions[0].buffData->rawVertexData,
                           newSkinPartition->vertexCount * newSkinPartition->partitions[0].buffData->vertexDesc.GetSize());
                }
                uint64_t UpdateSkinPartition_object[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
                UpdateSkinPartition_object[0] = NIOVTaskUpdateSkinPartitionvtable;

                uint64_t *skinInstPtr = (uint64_t *) (geo->GetGeometryRuntimeData().skinInstance.get());
                uint64_t *skinPartPtr = (uint64_t *) (newSkinPartition.get());
                UpdateSkinPartition_object[1] = (uint64_t) skinPartPtr;
                UpdateSkinPartition_object[2] = (uint64_t) skinInstPtr;
                auto RunNIOVTaskUpdateSkinPartition = ((void (*)(uint64_t *))((uint64_t *) UpdateSkinPartition_object[0])[0]);
                RunNIOVTaskUpdateSkinPartition(UpdateSkinPartition_object);
            }
        }
    }
    static void (*UpdateFaceModel)(RE::NiNode *node) = (void (*)(RE::NiNode *)) 0x0;
    static auto OriginalFaceApplyMorph =
        (void (*)(RE::BSFaceGenManager *, RE::BSFaceGenNiNode *, RE::TESNPC *, RE::BSFixedString *morphName, float relative)) nullptr;
    typedef struct {
            RE::NiNode *fg_node;
            RE::TESNPC *npc;
            float relative;
            std::string morphName;
            RE::ActorHandle handle;
    } FaceMorphData;
    std::map<std::tuple<RE::NiNode *, RE::TESNPC *, std::string>, FaceMorphData> queued_morphs;
    static void FaceApplyMorphHook(RE::BSFaceGenManager *fg_m, RE::BSFaceGenNiNode *fg_node, RE::TESNPC *npc, RE::BSFixedString *morphName,
                                   float relative) {
        if (morphName) {
            if (fg_node) {
                if (npc) {
                    RE::ActorHandle handle = fg_node->GetRuntimeData().unk15C;
                    std::lock_guard<std::recursive_mutex> l(queued_morphs_mutex);
                    if (queued_morphs.contains(std::make_tuple(fg_node, npc, std::string(morphName->c_str())))) {
                        relative += queued_morphs[std::make_tuple(fg_node, npc, std::string(morphName->c_str()))].relative;
                    }

                    queued_morphs.insert_or_assign(std::make_tuple(fg_node, npc, std::string(morphName->c_str())),
                                                   FaceMorphData(fg_node, npc, relative, std::string(morphName->c_str()), handle));
                    if (multi_morph_tasks_scheduled == 0) {
                        multi_morph_tasks_scheduled += 1;
                        std::thread t([] {
                            std::this_thread::sleep_for(std::chrono::milliseconds(500));
                            SKSE::GetTaskInterface()->AddTask([]() {
                                std::lock_guard<std::recursive_mutex> l(queued_morphs_mutex);
                                multi_morph_tasks_scheduled = 0;
                                std::map<std::tuple<RE::NiNode *, RE::TESNPC *, std::string>, FaceMorphData> copy_queued_morphs(
                                    queued_morphs);
                                queued_morphs.clear();
                                std::unordered_set<RE::ActorHandle*> updated_actors;
                                std::unordered_set<uint32_t> native_handles;
                                for (auto p: copy_queued_morphs) {
                                    if (auto actor = p.second.handle.get()) {
                                        if (actor->Is3DLoaded()) {
                                            RE::BSFixedString morphName(p.second.morphName);
                                            if (actor->GetFaceNodeSkinned() == p.second.fg_node ||
                                                actor->GetFaceNode() == p.second.fg_node) {
                                                OriginalFaceApplyMorph(RE::BSFaceGenManager::GetSingleton(),
                                                                       (RE::BSFaceGenNiNode *) p.second.fg_node, p.second.npc, &morphName,
                                                                       p.second.relative);
                                            }
                                            if (!native_handles.contains((p.second.handle.native_handle()))) {
                                                native_handles.insert(p.second.handle.native_handle());
                                                updated_actors.insert(&(p.second.handle));
                                            }
                                        }
                                    }
                                }

                                for (auto &ah: updated_actors) {
                                    if (auto actor = ah->get()) {
                                        if (actor->Is3DLoaded()) {
                                            if (auto node = actor->GetFaceNodeSkinned()) {
                                                UpdateFaceModel(node);
                                                WalkRecalculateNormals(node);
                                            }
                                        }
                                        
                                    }
                                }
                            });
                        });
                        t.detach();
                    }
                    return;
                }
            }
        }
        OriginalFaceApplyMorph(fg_m, fg_node, npc, morphName, relative);
    }

    static void (*ApplyMorphsHookFaceNormalsDetour)(void *e, RE::TESActorBase *,
                                                    RE::BSFaceGenNiNode *) = (void (*)(void *, RE::TESActorBase *,
                                                                                       RE::BSFaceGenNiNode *)) 0x0;
    static void ApplyMorphsHookFaceNormals(void *morphInterface, RE::TESActorBase *base, RE::BSFaceGenNiNode *node) {
        ApplyMorphsHookFaceNormalsDetour(morphInterface, base, node);
        if (node) {
            if (auto actor = node->GetRuntimeData().unk15C.get()) {
                if (actor->Is3DLoaded()) {
                    if (auto facenode = actor->GetFaceNodeSkinned()) {
                        UpdateFaceModel(facenode);
                        WalkRecalculateNormals(facenode);
                    }
                }
            }
            WalkRecalculateNormals(node);
        }
    }
    static void (*ApplyMorphHookFaceNormalsDetour)(void *e, RE::TESNPC *, RE::BGSHeadPart *,
                                                   RE::BSFaceGenNiNode *) = (void (*)(void *e, RE::TESNPC *, RE::BGSHeadPart *,
                                                                                      RE::BSFaceGenNiNode *)) 0x0;
    static void ApplyMorphHookFaceNormals(void *morphInterface, RE::TESNPC *npc, RE::BGSHeadPart *part, RE::BSFaceGenNiNode *node) {
        ApplyMorphHookFaceNormalsDetour(morphInterface, npc, part, node);
        if (node) {
            if (auto actor = node->GetRuntimeData().unk15C.get()) {
                if (actor->Is3DLoaded()) {
                    if (auto facenode = actor->GetFaceNodeSkinned()) {
                        UpdateFaceModel(facenode);
                        WalkRecalculateNormals(facenode);
                    }
                }
            }
            WalkRecalculateNormals(node);
        }
    }
    static void (*ApplyMorphsHookBodyNormalsDetour)(void *e, RE::TESObjectREFR *, RE::NiNode *, bool isAttaching,
                                                    bool defer) = (void (*)(void *, RE::TESObjectREFR *, RE::NiNode *, bool isAttaching,
                                                                            bool defer)) 0x0;
    static void ApplyMorphsHookBodyNormals(void *morphInterface, RE::TESObjectREFR *refr, RE::NiNode *node, bool isAttaching, bool defer) {
        ApplyMorphsHookBodyNormalsDetour(morphInterface, refr, node, isAttaching, defer);
        if (node) {
            if (node->AsNode()) {
                WalkRecalculateNormals(node);
                if (auto actor = refr->As<RE::Actor>()) {
                    if (actor->Is3DLoaded()) {
                        if (auto facenode = actor->GetFaceNodeSkinned()) {
                            UpdateFaceModel(facenode);
                            WalkRecalculateNormals(facenode);
                        }
                    }
                }
            }
            WalkRecalculateNormals(node);
        }
    }
    void GameEventHandler::onLoad() {
        logger::info("onLoad()");
        Hooks::install();
    }

    void GameEventHandler::onPostLoad() {
        logger::info("onPostLoad()");
    }

    static std::atomic<uint32_t> skee_loaded = 0;
    void GameEventHandler::onPostPostLoad() {
        if (HMODULE handle = GetModuleHandleA("skee64.dll")) {
            MODULEINFO skee64_info;
            GetModuleInformation(GetCurrentProcess(), handle, &skee64_info, sizeof(skee64_info));
            logger::info("Got SKEE64 information");
            uint32_t expected = 0;
            if (skee_loaded.compare_exchange_strong(expected, 1) == true && expected == 0) {
                if ((skee64_info.SizeOfImage >= 0x16b478 + 7) &&
                    memcmp("BODYTRI", (void *) ((uintptr_t) skee64_info.lpBaseOfDll + (uintptr_t) 0x16b478), 7) == 0) {
                    UpdateFaceModel = (void (*)(RE::NiNode *)) REL::Offset(0x3dbda0).address();
                    NIOVTaskUpdateSkinPartitionvtable = (uint64_t) skee64_info.lpBaseOfDll + 0x16d118;
                    ApplyMorphHookFaceNormalsDetour = (void (*)(void *e, RE::TESNPC *, RE::BGSHeadPart *, RE::BSFaceGenNiNode *))(
                        (uint64_t) skee64_info.lpBaseOfDll + 0x5f480);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) ApplyMorphHookFaceNormalsDetour, &ApplyMorphHookFaceNormals);
                    DetourTransactionCommit();
                    ApplyMorphsHookFaceNormalsDetour =
                        (void (*)(void *, RE::TESActorBase *, RE::BSFaceGenNiNode *))((uint64_t) skee64_info.lpBaseOfDll + 0x5f9e0);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) ApplyMorphsHookFaceNormalsDetour, &ApplyMorphsHookFaceNormals);
                    DetourTransactionCommit();
                    ApplyMorphsHookBodyNormalsDetour = (void (*)(void *, RE::TESObjectREFR *, RE::NiNode *, bool isAttaching, bool defer))(
                        (uint64_t) skee64_info.lpBaseOfDll + 0x8460);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) ApplyMorphsHookBodyNormalsDetour, &ApplyMorphsHookBodyNormals);
                    DetourTransactionCommit();
                    OriginalFaceApplyMorph = (void (*)(RE::BSFaceGenManager *, RE::BSFaceGenNiNode *, RE::TESNPC *,
                                                       RE::BSFixedString *morphName, float relative)) REL::Offset(0x3d2220)
                                                 .address();
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) OriginalFaceApplyMorph, &FaceApplyMorphHook);
                    DetourTransactionCommit();
                    logger::info("SKEE64 1597 normal recaclulation backported");
                }
                uint8_t signature1170[] = {0xff, 0x90, 0xf0, 0x03, 0x00, 0x00};
                if ((skee64_info.SizeOfImage >= 0xc2950 + 0x40) &&
                    memcmp(signature1170, (void *) ((uintptr_t) skee64_info.lpBaseOfDll + (uintptr_t) 0xc2950 + (uintptr_t) 0x28),
                           sizeof(signature1170)) == 0) {
                    UpdateFaceModel = (void (*)(RE::NiNode *)) REL::Offset(0x435c50).address();
                    NIOVTaskUpdateSkinPartitionvtable = (uint64_t) skee64_info.lpBaseOfDll + 0x1d4c60;
                    ApplyMorphsHookFaceNormalsDetour =
                        (void (*)(void *, RE::TESActorBase *, RE::BSFaceGenNiNode *))((uint64_t) skee64_info.lpBaseOfDll + 0xb9a40);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) ApplyMorphsHookFaceNormalsDetour, &ApplyMorphsHookFaceNormals);
                    DetourTransactionCommit();
                    ApplyMorphsHookBodyNormalsDetour = (void (*)(void *, RE::TESObjectREFR *, RE::NiNode *, bool isAttaching, bool defer))(
                        (uint64_t) skee64_info.lpBaseOfDll + 0x1cd70);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) ApplyMorphsHookBodyNormalsDetour, &ApplyMorphsHookBodyNormals);
                    DetourTransactionCommit();
                    OriginalFaceApplyMorph = (void (*)(RE::BSFaceGenManager *, RE::BSFaceGenNiNode *, RE::TESNPC *,
                                                       RE::BSFixedString *morphName, float relative)) REL::Offset(0x42b610)
                                                 .address();
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) OriginalFaceApplyMorph, &FaceApplyMorphHook);
                    DetourTransactionCommit();
                    /*
                    UpdateMorphsHookBodyDetour =
                        (void (*)(void *, RE::TESObjectREFR *, bool))((uint64_t) skee64_info.lpBaseOfDll + 0x167b0);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) UpdateMorphsHookBodyDetour, UpdateMorphsHookBody);
                    DetourTransactionCommit();
                    */
                    /*
                    UpdateMorphsHookBodyDetour2 =
                        (void (*)(void *, RE::TESObjectREFR *, bool))((uint64_t) skee64_info.lpBaseOfDll + 0x6860);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) UpdateMorphsHookBodyDetour2, UpdateMorphsHookBody2);
                    DetourTransactionCommit();
                    */
                    /*
                    DoubleMorphCallbackDetour =
                        (void (*)(void *menu, float newValue, uint32_t slider))((uint64_t) skee64_info.lpBaseOfDll + 0x8ae10);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) DoubleMorphCallbackDetour, &DoubleMorphCallback);
                    DetourTransactionCommit();
                    */
                    /*
                    if (normalfix == nullptr) {
                        normalfix = new Update3DModelRecalc();
                        SKSE::GetNiNodeUpdateEventSource()->AddEventSink<SKSE::NiNodeUpdateEvent>(normalfix);
                    }*/
                    logger::info("SKEE64 1170 extra normal recalculation added");
                }
            }
        }

        logger::info("onPostPostLoad()");
    }

    void GameEventHandler::onInputLoaded() {
        logger::info("onInputLoaded()");
    }

    void GameEventHandler::onDataLoaded() {
        logger::info("onDataLoaded()");
    }

    void GameEventHandler::onNewGame() {
        logger::info("onNewGame()");
    }

    void GameEventHandler::onPreLoadGame() {
        logger::info("onPreLoadGame()");
    }

    void GameEventHandler::onPostLoadGame() {
        logger::info("onPostLoadGame()");
    }

    void GameEventHandler::onSaveGame() {
        logger::info("onSaveGame()");
    }

    void GameEventHandler::onDeleteGame() {
        logger::info("onDeleteGame()");
    }
}  // namespace plugin