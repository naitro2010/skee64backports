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
#include "ini.h"
namespace plugin {

#undef GetObject
    static uint64_t NIOVTaskUpdateSkinPartitionvtable = 0x0;
    static void (*UpdateFaceModel)(RE::NiNode *node) = (void (*)(RE::NiNode *)) 0x0;
    static void (*ApplyMorphsHookFaceNormalsDetour)(void *e, RE::TESActorBase *,
                                                    RE::BSFaceGenNiNode *) = (void (*)(void *, RE::TESActorBase *,
                                                                                       RE::BSFaceGenNiNode *)) 0x0;
    std::map<RE::FormID, std::atomic_uint32_t> actor_queued_recalculations;
    std::recursive_mutex actor_queued_recalc_mutex;
    std::map<RE::FormID, std::atomic_uint32_t> actor_queued_morphs;
    std::map<std::pair<RE::FormID,RE::NiNode*>, std::atomic_uint32_t> actor_queued_morphs2;
    std::map<RE::FormID, std::chrono::time_point<std::chrono::steady_clock>> actor_morph_update_times;
    std::map<std::pair<RE::FormID, RE::NiNode *>, std::chrono::time_point<std::chrono::steady_clock>> actor_morph_apply_times;
    std::recursive_mutex actor_queued_morphs_mutex;
    std::atomic_uint32_t queued_recalculations = 0;
    static long long morph_delay = 500;
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
                //logger::info("Recalc1");
                if (geo->GetGeometryRuntimeData().skinInstance == nullptr) {
                    continue;
                }
                //logger::info("Recalc2");
                if (geo->GetGeometryRuntimeData().skinInstance->skinPartition == nullptr) {
                    continue;
                }
                //logger::info("Recalc3");
                if ((!geo->GetGeometryRuntimeData().vertexDesc.HasFlag(RE::BSGraphics::Vertex::VF_NORMAL)) &&
                    (!geo->GetGeometryRuntimeData().vertexDesc.HasFlag(RE::BSGraphics::Vertex::VF_TANGENT))) {
                    continue;
                }
                //logger::info("Recalc4");
                if (!geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect] ||
                    !geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect]->GetRTTI()->IsKindOf(
                        (RE::NiRTTI *) RE::BSLightingShaderProperty::Ni_RTTI.address())) {
                    continue;
                }
                // logger::info("Recalc5");
                RE::BSLightingShaderProperty *property =
                    (RE::BSLightingShaderProperty *) geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect].get();
                auto material = property->material;
                if (!material) {
                    continue;
                }
                // logger::info("Recalc6");
                RE::NiPointer<RE::NiObject> newPartition = nullptr;
                geo->GetGeometryRuntimeData().skinInstance->skinPartition->CreateDeepCopy(newPartition);
                if (!newPartition) {
                    continue;
                }
                // logger::info("Recalc7");
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
                //logger::info("Recalc8");
                for (uint32_t p = 1; p < newSkinPartition->partitions.size(); ++p) {
                    auto &pPartition = newSkinPartition->partitions[p];
                    memcpy(pPartition.buffData->rawVertexData, newSkinPartition->partitions[0].buffData->rawVertexData,
                           newSkinPartition->vertexCount * newSkinPartition->partitions[0].buffData->vertexDesc.GetSize());
                }
                // logger::info("Recalc9");
                uint64_t *UpdateSkinPartition_object = new uint64_t[6];
                UpdateSkinPartition_object[0] = NIOVTaskUpdateSkinPartitionvtable;

                uint64_t *skinInstPtr = (uint64_t *) geo->GetGeometryRuntimeData().skinInstance.get();
                uint64_t *skinPartPtr = (uint64_t *) newSkinPartition.get();
                UpdateSkinPartition_object[1] = (uint64_t) skinPartPtr;
                UpdateSkinPartition_object[2] = (uint64_t) skinInstPtr;
                UpdateSkinPartition_object[3] = 0x0;
                UpdateSkinPartition_object[4] = 0x0;
                UpdateSkinPartition_object[5] = 0x0;
                auto RunNIOVTaskUpdateSkinPartition = ((void (*)(uint64_t *))((uint64_t *) UpdateSkinPartition_object[0])[0]);
                RunNIOVTaskUpdateSkinPartition(UpdateSkinPartition_object);
                // logger::info("Recalc10");
                free(UpdateSkinPartition_object);
            }
        }
    }

    static void (*DoubleMorphCallbackDetour)(void *menu, float newValue,
                                             uint32_t slider) = (void (*)(void *menu, float newValue, uint32_t slider)) 0x0;

    static void DoubleMorphCallback(void *menu, float newValue, uint32_t slider) {
        DoubleMorphCallbackDetour(menu, newValue, slider);
        if (RE::PlayerCharacter::GetSingleton()) {
            auto handle = RE::PlayerCharacter::GetSingleton()->GetHandle();
            uint32_t expected = 0;
            queued_recalculations.compare_exchange_weak(expected, 1);
            if (expected == 0) {
                SKSE::GetTaskInterface()->AddTask([handle]() {
                    uint32_t expected = 1;
                    queued_recalculations.compare_exchange_weak(expected, 0);
                    if (auto actor = handle.get()) {
                        if (auto obj = actor->Get3D1(false)) {
                            if (obj->AsNode()) {
                                logger::info("Recalculating 3P");
                                WalkRecalculateNormals(obj->AsNode());
                            }
                        }
                        if (auto obj = actor->Get3D1(true)) {
                            if (obj->AsNode()) {
                                logger::info("Recalculating 1P");
                                WalkRecalculateNormals(obj->AsNode());
                            }
                        }
                        if (auto node = actor->GetFaceNode()) {
                            logger::info("Recalculating Face");
                            UpdateFaceModel(node);
                            WalkRecalculateNormals(node);
                        }
                    }
                });
            }
        }
    }

    class Update3DModelRecalc : public RE::BSTEventSink<SKSE::NiNodeUpdateEvent> {
            RE::BSEventNotifyControl ProcessEvent(const SKSE::NiNodeUpdateEvent *a_event,
                                                  RE::BSTEventSource<SKSE::NiNodeUpdateEvent> *a_eventSource) {
                if (a_event && a_event->reference && a_event->reference->As<RE::Actor>()) {
                    auto handle = a_event->reference->As<RE::Actor>()->GetHandle();
                    {
                        bool do_recalc = false;
                        RE::FormID FID = a_event->reference->As<RE::Actor>()->formID;
                        {
                            std::lock_guard<std::recursive_mutex> l(actor_queued_recalc_mutex);
                            if (!actor_queued_recalculations.contains(FID)) {
                                actor_queued_recalculations.insert_or_assign(FID, 0);
                            }
                            if (actor_queued_recalculations[FID].fetch_add(1) < 2) {
                                do_recalc = true;
                            } else {
                                actor_queued_recalculations[FID].fetch_sub(1);
                            }
                        }
                        
                        if (do_recalc == true) {
                            SKSE::GetTaskInterface()->AddTask([handle, FID]() {
                                {
                                    std::lock_guard<std::recursive_mutex> l(actor_queued_recalc_mutex);
                                    actor_queued_recalculations[FID].fetch_sub(1);
                                }
                                if (auto actor = handle.get()) {
                                    if (auto obj = actor->Get3D1(false)) {
                                        if (obj->AsNode()) {
                                            logger::info("Recalculating 3P");
                                            WalkRecalculateNormals(obj->AsNode());
                                        }
                                    }
                                    if (auto obj = actor->Get3D1(true)) {
                                        if (obj->AsNode()) {
                                            logger::info("Recalculating 1P");
                                            WalkRecalculateNormals(obj->AsNode());
                                        }
                                    }
                                    if (auto node = actor->GetFaceNode()) {
                                        logger::info("Recalculating Face");
                                        UpdateFaceModel(node);
                                        WalkRecalculateNormals(node);
                                    }
                                }
                            });
                        }
                    }
                }
                return RE::BSEventNotifyControl::kContinue;
            }
    };
    Update3DModelRecalc *normalfix = nullptr;

    static void ApplyMorphsHookFaceNormals(void *morphInterface, RE::TESActorBase *base, RE::BSFaceGenNiNode *node) {
        ApplyMorphsHookFaceNormalsDetour(morphInterface, base, node);

        if (node) {
            RE::NiPointer<RE::BSFaceGenNiNode> node_ptr(node);

            SKSE::GetTaskInterface()->AddTask([node_ptr]() {
                auto node = node_ptr.get();
                {
                    //logger::info("Recalc Caller 1");
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

    auto UpdateMorphsHookBodyDetour2 = (void (*)(void *, RE::TESObjectREFR *, bool)) 0x0;
    static void UpdateMorphsHookBody2(void *morphInterface, RE::TESObjectREFR *refr, bool defer) {
        if (refr && refr->As<RE::Actor>()) {
            bool do_morphs = false;
            RE::FormID FID = refr->formID;
            auto next_time = std::chrono::steady_clock::now();
            {
                std::lock_guard<std::recursive_mutex> l(actor_queued_morphs_mutex);
                if (!actor_queued_morphs.contains(FID)) {
                    actor_queued_morphs.insert_or_assign(FID, 0);
                }
                if (!actor_morph_update_times.contains(FID)) {
                    actor_morph_update_times.insert_or_assign(FID, next_time);
                }

                if (actor_queued_morphs[FID].fetch_add(1) < 2) {
                    do_morphs = true;
                } else {
                    actor_queued_morphs[FID].fetch_sub(1);
                }
            }
            if (do_morphs == true) {
                auto handle = refr->As<RE::Actor>()->GetHandle();
                std::thread([handle, FID, morphInterface, defer]() {
                    auto next_time = std::chrono::steady_clock::now();
                    {
                        std::lock_guard<std::recursive_mutex> l(actor_queued_morphs_mutex);
                        next_time = actor_morph_update_times[FID];
                    }
                    std::this_thread::sleep_until(next_time);
                    SKSE::GetTaskInterface()->AddTask([handle, FID, morphInterface, defer]() {
                        {
                            std::lock_guard<std::recursive_mutex> l(actor_queued_recalc_mutex);
                            actor_queued_recalculations[FID].fetch_sub(1);
                        }
                        {
                            std::lock_guard<std::recursive_mutex> l(actor_queued_morphs_mutex);
                            actor_morph_update_times.insert_or_assign(
                                FID, std::chrono::steady_clock::now() + std::chrono::milliseconds(morph_delay));
                        }
                        if (RE::ActorPtr actor = handle.get()) {
                            UpdateMorphsHookBodyDetour2(morphInterface, actor.get(), defer);
                        }
                        if (auto actor = handle.get()) {
                            if (auto obj = actor->Get3D1(false)) {
                                if (obj->AsNode()) {
                                    logger::info("Recalculating 3P");
                                    WalkRecalculateNormals(obj->AsNode());
                                }
                            }
                            if (auto obj = actor->Get3D1(true)) {
                                if (obj->AsNode()) {
                                    logger::info("Recalculating 1P");
                                    WalkRecalculateNormals(obj->AsNode());
                                }
                            }
                            if (auto node = actor->GetFaceNode()) {
                                logger::info("Recalculating Face");
                                UpdateFaceModel(node);
                                WalkRecalculateNormals(node);
                            }
                        }
                    });
                }).detach();
            }
        }
    }


    auto UpdateMorphsHookBodyDetour = (void (*)(void *, RE::TESObjectREFR *, bool))0x0;
    static void UpdateMorphsHookBody(void *morphInterface, RE::TESObjectREFR *refr,bool defer) {
        if (refr && refr->As<RE::Actor>()) {
            bool do_morphs = false;
            RE::FormID FID = refr->formID;
            auto next_time = std::chrono::steady_clock::now();
            {
                std::lock_guard<std::recursive_mutex> l(actor_queued_morphs_mutex);
                if (!actor_queued_morphs.contains(FID)) {
                    actor_queued_morphs.insert_or_assign(FID, 0);
                }
                if (!actor_morph_update_times.contains(FID)) {
                    actor_morph_update_times.insert_or_assign(FID, next_time);
                }

                if (actor_queued_morphs[FID].fetch_add(1) < 2) {
                    do_morphs = true;
                } else {
                    actor_queued_morphs[FID].fetch_sub(1);
                }
            }
            if (do_morphs == true) {
                auto handle = refr->As<RE::Actor>()->GetHandle();
                std::thread([handle, FID, morphInterface, defer]() {
                    auto next_time = std::chrono::steady_clock::now();
                    { 
                        std::lock_guard<std::recursive_mutex> l(actor_queued_morphs_mutex); 
                        next_time = actor_morph_update_times[FID];
                    }
                    std::this_thread::sleep_until(next_time);
                    SKSE::GetTaskInterface()->AddTask([handle, FID, morphInterface, defer]() {
                        {
                            std::lock_guard<std::recursive_mutex> l(actor_queued_recalc_mutex);
                            actor_queued_recalculations[FID].fetch_sub(1);
                        }
                        {
                            std::lock_guard<std::recursive_mutex> l(actor_queued_morphs_mutex);
                            actor_morph_update_times.insert_or_assign(FID,std::chrono::steady_clock::now() +
                                                                      std::chrono::milliseconds(morph_delay));
                        }
                        if (RE::ActorPtr actor = handle.get()) {
                            UpdateMorphsHookBodyDetour(morphInterface, actor.get(), defer);

                        }
                        if (auto actor = handle.get()) {
                            if (auto obj = actor->Get3D1(false)) {
                                if (obj->AsNode()) {
                                    logger::info("Recalculating 3P");
                                    WalkRecalculateNormals(obj->AsNode());
                                }
                            }
                            if (auto obj = actor->Get3D1(true)) {
                                if (obj->AsNode()) {
                                    logger::info("Recalculating 1P");
                                    WalkRecalculateNormals(obj->AsNode());
                                }
                            }
                            if (auto node = actor->GetFaceNode()) {
                                logger::info("Recalculating Face");
                                UpdateFaceModel(node);
                                WalkRecalculateNormals(node);
                            }
                        }
                    });
                }).detach();
            }
        }
        
    }
    static void ApplyMorphsHookBodyNormals(void *morphInterface, RE::TESObjectREFR *refr, RE::NiNode *node, bool isAttaching, bool defer) {
        if (refr && refr->As<RE::Actor>()) {
            
            bool do_morphs = false;
            RE::FormID FID = refr->formID;
            auto next_time = std::chrono::steady_clock::now();
            std::pair refr_node(FID, node);
            {
                std::lock_guard<std::recursive_mutex> l(actor_queued_morphs_mutex);
                if (!actor_queued_morphs2.contains(refr_node)) {
                    actor_queued_morphs2.insert_or_assign(refr_node, 0);
                }
                if (!actor_morph_apply_times.contains(refr_node)) {
                    actor_morph_apply_times.insert_or_assign(refr_node, next_time);
                }

                if (actor_queued_morphs2[refr_node].fetch_add(1) < 2) {
                    do_morphs = true;
                } else {
                    actor_queued_morphs2[refr_node].fetch_sub(1);
                }
            }
            
            // logger::info("Recalc Caller 2");
            if (node) {
                
                if (node->AsNode()) {
                    RE::NiPointer node_ptr(node);
                    if (do_morphs == true) {
                        
                        auto handle = refr->As<RE::Actor>()->GetHandle();
                        std::thread([morphInterface, handle, node_ptr, refr_node, isAttaching, defer]() {
                            auto next_time = std::chrono::steady_clock::now();
                            {
                                std::lock_guard<std::recursive_mutex> l(actor_queued_morphs_mutex);
                                next_time = actor_morph_apply_times[refr_node];
                            }
                            std::this_thread::sleep_until(next_time);
                            SKSE::GetTaskInterface()->AddTask([morphInterface, handle, node_ptr, refr_node, isAttaching, defer]() {
                                {
                                    auto refr = handle.get();
                                    if (refr) {
                                        {
                                            std::lock_guard<std::recursive_mutex> l(actor_queued_morphs_mutex);
                                            actor_morph_apply_times.insert_or_assign(
                                                refr_node, std::chrono::steady_clock::now() + std::chrono::milliseconds(morph_delay));
                                        }
                                        ApplyMorphsHookBodyNormalsDetour(morphInterface, refr.get(), node_ptr.get(), isAttaching, defer);
                                        auto node = node_ptr.get();
                                        WalkRecalculateNormals(node);
                                    }
                                    actor_queued_morphs2[refr_node].fetch_sub(1);
                                }
                            });
                        }).detach();
                    }
                    if (auto player = RE::PlayerCharacter::GetSingleton()) {
                        auto handle = player->GetHandle();
                        SKSE::GetTaskInterface()->AddTask([handle]() {
                            if (auto actor = handle.get()) {
                                if (auto facenode = actor->GetFaceNode()) {
                                    // logger::info("Recalc Caller 2");
                                    UpdateFaceModel(facenode);
                                    WalkRecalculateNormals(facenode);
                                }
                                if (auto facenode = actor->GetFaceNodeSkinned()) {
                                    //logger::info("Recalc Caller 3");
                                    UpdateFaceModel(facenode);
                                    WalkRecalculateNormals(facenode);
                                }
                            }
                        });
                    }
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
        mINI::INIFile file("Data\\skse\\plugins\\skee64backports.ini");
        mINI::INIStructure ini;
        if (file.read(ini) == false) {
            ini["skee64backports"]["maxmorphdelay"] = "500";
            file.write(ini);
        } else {
            file.generate(ini);
            morph_delay = atoll(ini["skee64backports"]["maxmorphdelay"].c_str());
            if (morph_delay < 0) {
                morph_delay = 0;
            }
            
        }
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

                    UpdateMorphsHookBodyDetour = (void (*)(void *, RE::TESObjectREFR *, bool)) ((uint64_t) skee64_info.lpBaseOfDll + 0x86d0);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) UpdateMorphsHookBodyDetour, UpdateMorphsHookBody);
                    DetourTransactionCommit();

                    DoubleMorphCallbackDetour =
                        (void (*)(void *menu, float newValue, uint32_t slider))((uint64_t) skee64_info.lpBaseOfDll + 0x3c810);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) DoubleMorphCallbackDetour, &DoubleMorphCallback);
                    DetourTransactionCommit();
                    if (normalfix == nullptr) {
                        normalfix = new Update3DModelRecalc();
                        SKSE::GetNiNodeUpdateEventSource()->AddEventSink<SKSE::NiNodeUpdateEvent>(normalfix);
                    }
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

                    UpdateMorphsHookBodyDetour = (void (*)(void *, RE::TESObjectREFR *, bool))((uint64_t) skee64_info.lpBaseOfDll + 0x167b0);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) UpdateMorphsHookBodyDetour, UpdateMorphsHookBody);
                    DetourTransactionCommit();

                    UpdateMorphsHookBodyDetour2 =
                        (void (*)(void *, RE::TESObjectREFR *, bool))((uint64_t) skee64_info.lpBaseOfDll + 0x6860);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) UpdateMorphsHookBodyDetour2, UpdateMorphsHookBody2);
                    DetourTransactionCommit();

                    DoubleMorphCallbackDetour =
                        (void (*)(void *menu, float newValue, uint32_t slider))((uint64_t) skee64_info.lpBaseOfDll + 0x8ae10);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) DoubleMorphCallbackDetour, &DoubleMorphCallback);
                    DetourTransactionCommit();
                    if (normalfix == nullptr) {
                        normalfix = new Update3DModelRecalc();
                        SKSE::GetNiNodeUpdateEventSource()->AddEventSink<SKSE::NiNodeUpdateEvent>(normalfix);
                    }
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