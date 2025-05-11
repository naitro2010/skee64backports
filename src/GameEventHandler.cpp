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
                logger::info("Recalc1");
                if (geo->GetGeometryRuntimeData().skinInstance == nullptr) {
                    continue;
                }
                logger::info("Recalc2");
                if (geo->GetGeometryRuntimeData().skinInstance->skinPartition == nullptr) {
                    continue;
                }
                logger::info("Recalc3");
                if ((!geo->GetGeometryRuntimeData().vertexDesc.HasFlag(RE::BSGraphics::Vertex::VF_NORMAL)) &&
                    (!geo->GetGeometryRuntimeData().vertexDesc.HasFlag(RE::BSGraphics::Vertex::VF_TANGENT))) {
                    continue;
                }
                logger::info("Recalc4");
                if (!geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect] ||
                    !geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect]
                        ->GetRTTI()->IsKindOf(
                        (RE::NiRTTI*)
                        RE::BSLightingShaderProperty::Ni_RTTI.address())) {
                    continue;
                }
                logger::info("Recalc5");
                RE::BSLightingShaderProperty *property =
                    (RE::BSLightingShaderProperty *) geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect].get();
                auto material = property->material;
                if (!material) {
                    continue;
                }
                logger::info("Recalc6");
                RE::NiPointer<RE::NiObject> newPartition = nullptr;
                geo->GetGeometryRuntimeData().skinInstance->skinPartition->CreateDeepCopy(newPartition);
                if (!newPartition) {
                    continue;
                }
                logger::info("Recalc7");
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
                logger::info("Recalc8");
                for (uint32_t p = 1; p < newSkinPartition->partitions.size(); ++p) {
                    auto &pPartition = newSkinPartition->partitions[p];
                    memcpy(pPartition.buffData->rawVertexData, newSkinPartition->partitions[0].buffData->rawVertexData,
                           newSkinPartition->vertexCount * newSkinPartition->partitions[0].buffData->vertexDesc.GetSize());
                }
                logger::info("Recalc9");
                uint64_t *UpdateSkinPartition_object = new uint64_t[6];
                UpdateSkinPartition_object[0] = NIOVTaskUpdateSkinPartitionvtable;
                
                uint64_t* skinInstPtr = (uint64_t*) &geo->GetGeometryRuntimeData().skinInstance;
                uint64_t* skinPartPtr = (uint64_t*) &newSkinPartition;
                UpdateSkinPartition_object[1] = (uint64_t) *skinPartPtr;
                UpdateSkinPartition_object[2] = (uint64_t) *skinInstPtr;
                UpdateSkinPartition_object[3] = 0x0;
                UpdateSkinPartition_object[4] = 0x0;
                UpdateSkinPartition_object[5] = 0x0;
                auto RunNIOVTaskUpdateSkinPartition = ((void (*)(uint64_t *))((uint64_t *) UpdateSkinPartition_object[0])[0]);
                RunNIOVTaskUpdateSkinPartition(UpdateSkinPartition_object);
                logger::info("Recalc10");
                free(UpdateSkinPartition_object);
            }
        }
    }
    static void (*UpdateFaceModel)(RE::NiNode *node) = (void (*)(RE::NiNode *)) 0x0;
    static void (*ApplyMorphsHookFaceNormalsDetour)(void *e, RE::TESActorBase *,
                                                    RE::BSFaceGenNiNode *) = (void (*)(void *, RE::TESActorBase *,
                                                                                       RE::BSFaceGenNiNode *)) 0x0;
    static void ApplyMorphsHookFaceNormals(void *morphInterface, RE::TESActorBase *base, RE::BSFaceGenNiNode *node) {
        ApplyMorphsHookFaceNormalsDetour(morphInterface, base, node);
        
        if (node) {
            RE::NiPointer<RE::BSFaceGenNiNode> node_ptr(node);
            
            SKSE::GetTaskInterface()->AddTask([node_ptr]() {
                auto node = node_ptr.get();
                {
                    logger::info("Recalc Caller 1");
                    UpdateFaceModel(node);
                    WalkRecalculateNormals(node);
                }
            });
        }
    }
    /*
    static void (*ApplyMorphHookFaceNormalsDetour)(void *e, RE::TESNPC*,RE::BGSHeadPart*,
                                                   RE::BSFaceGenNiNode *) = (void (*)(void *e, RE::TESNPC *, RE::BGSHeadPart *,
                                                                                      RE::BSFaceGenNiNode *)) 0x0;
    static void ApplyMorphHookFaceNormals(void *morphInterface,RE::TESNPC*npc, RE::BGSHeadPart *part, RE::BSFaceGenNiNode *node) {
        if (node) {
            ApplyMorphHookFaceNormalsDetour(morphInterface, npc,part,node);
            UpdateFaceModel(node);
            WalkRecalculateNormals(node);
        }
    }
    */
    static void (*ApplyMorphsHookBodyNormalsDetour)(void *e, RE::TESObjectREFR *, RE::NiNode *, bool isAttaching,
                                                    bool defer) = (void (*)(void *, RE::TESObjectREFR *, RE::NiNode *, bool isAttaching,
                                                                            bool defer)) 0x0;
    static void ApplyMorphsHookBodyNormals(void *morphInterface, RE::TESObjectREFR *refr, RE::NiNode *node, bool isAttaching, bool defer) {
        ApplyMorphsHookBodyNormalsDetour(morphInterface, refr, node, isAttaching, defer);
        logger::info("Recalc Caller 2");
        if (node) {
            if (node->AsNode()) {
                RE::NiPointer node_ptr(node);
                SKSE::GetTaskInterface()->AddTask([node_ptr]() {
                    {
                        auto node = node_ptr.get();
                        WalkRecalculateNormals(node);
                    }
                });
                if (auto player=RE::PlayerCharacter::GetSingleton()) {
                    auto handle = player->GetHandle();
                    SKSE::GetTaskInterface()->AddTask([handle]() {
                        if (auto actor = handle.get()) {
                            if (auto facenode = actor->GetFaceNode()) {
                                logger::info("Recalc Caller 2");
                                UpdateFaceModel(facenode);
                                WalkRecalculateNormals(facenode);
                            }
                            if (auto facenode = actor->GetFaceNodeSkinned()) {
                                logger::info("Recalc Caller 3");
                                UpdateFaceModel(facenode);
                                WalkRecalculateNormals(facenode);
                            }
                        }
                    });
                }
                
            }
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
                    
                    logger::info("SKEE64 1597 normal recaclulation backported");
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