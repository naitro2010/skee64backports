#pragma warning(disable : 4100 4189 4244 4505)
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
    static uint32_t multi_morph_tasks_scheduled = 0;
    static uint32_t recalculate_tasks_scheduled = 0;
    static std::recursive_mutex queued_recalcs_mutex;
    static std::recursive_mutex queued_morphs_mutex;
    static std::recursive_mutex preset_mutex;
    static bool applying_slider = false;
    auto task_pool_ptr = (bool (*)(void)) nullptr;
    static bool is_main_or_task_thread() {
        auto main = RE::Main::GetSingleton();
        auto isVR = REL::Module::get().IsVR();
        auto main_thread_id = main->threadID;
        if (isVR) {
            main_thread_id = ((uint64_t) main->instance) & 0xFFFFFFFF;
        }
        auto current_thread_id = std::this_thread::get_id()._Get_underlying_id();
        if (current_thread_id == main_thread_id || (task_pool_ptr != nullptr && !task_pool_ptr())) {
            return true;
        }
        return false;
    }
    RE::TESObjectREFR *GetUserDataFixed(RE::NiAVObject *obj) {
        auto *userData = REL::RelocateMember<RE::TESObjectREFR *>(obj, 0x0F8, 0x110);
        if (userData) {
            return userData;
        }
        if (obj->parent) {
            return GetUserDataFixed(obj->parent);
        }
        return nullptr;
    }
    typedef struct {
            RE::NiNode *fg_node;
            RE::TESNPC *npc;
            float relative;
            std::string morphName;
            RE::ActorHandle handle;
    } FaceMorphData;
    typedef struct {
            RE::FormID actor_id;
            RE::ActorHandle actor_handle;
            std::queue<RE::NiPointer<RE::BSGeometry>> geo_queue;
    } RecalcProgressData;
    std::map<std::tuple<RE::NiNode *, RE::TESNPC *, std::string>, FaceMorphData> queued_morphs;
    std::unordered_map<RE::FormID, RE::ActorHandle> queued_recalcs;
    std::recursive_mutex recalcs_in_progress_lock;
    std::unordered_map<RE::FormID, RecalcProgressData> recalcs_in_progress;
    uint64_t recalc_tasks_started = 0;
    static RE::NiSkinPartition *ProcessRecalcQueue(RE::NiPointer<RE::BSGeometry> &geo) {
        if (GetUserDataFixed(geo.get()) == nullptr) {
            logger::info("geometry doesn't have user data");
            return nullptr;
        }
        if (!geo->parent) {
            logger::info("geometry has no parent");
            return nullptr;
        }
        logger::info("old geo ref count before recalc {} {}", geo->name.c_str(), geo->GetRefCount());
        if (geo->GetRefCount() <= 1) {
            logger::info("geometry not referenced by anything else");
            return nullptr;
        }
        if (geo->GetGeometryRuntimeData().skinInstance == nullptr) {
            return nullptr;
        }
        if (geo->GetGeometryRuntimeData().skinInstance->skinPartition == nullptr) {
            return nullptr;
        }
        if ((!geo->GetGeometryRuntimeData().vertexDesc.HasFlag(RE::BSGraphics::Vertex::VF_NORMAL)) &&
            (!geo->GetGeometryRuntimeData().vertexDesc.HasFlag(RE::BSGraphics::Vertex::VF_TANGENT))) {
            return nullptr;
        }
        if (!geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect] ||
            !geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect]->GetRTTI()->IsKindOf(
                (RE::NiRTTI *) RE::BSShaderProperty::Ni_RTTI.address())) {
            return nullptr;
        }
        RE::BSShaderProperty *property =
            (RE::BSShaderProperty *) geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect].get();
        auto material = property->material;
        if (!material) {
            return nullptr;
        }

        RE::NiPointer<RE::NiSkinPartition> newSkinPartition = geo->GetGeometryRuntimeData().skinInstance->skinPartition;

        if (newSkinPartition->partitions.size() == 0) {
            return nullptr;
        }

        {
            NormalApplicatorBackported applicator(RE::NiPointer<RE::BSGeometry>((RE::BSGeometry *) geo.get()), newSkinPartition);
            applicator.Apply();
            for (uint32_t p = 1; p < newSkinPartition->partitions.size(); ++p) {
                auto &pPartition = newSkinPartition->partitions[p];
                memcpy(pPartition.buffData->rawVertexData, newSkinPartition->partitions[0].buffData->rawVertexData,
                       ((size_t) newSkinPartition->vertexCount) * newSkinPartition->partitions[0].buffData->vertexDesc.GetSize());
            }
            logger::info("new skin partition ref count before update {} {}", geo->name.c_str(), newSkinPartition->GetRefCount());
            logger::info("old skin instance ref count before update {} {}", geo->name.c_str(),
                         geo->GetGeometryRuntimeData().skinInstance->GetRefCount());
            uint64_t UpdateSkinPartition_object[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
            UpdateSkinPartition_object[0] = NIOVTaskUpdateSkinPartitionvtable;
            uint64_t *skinInstPtr = (uint64_t *) (geo->GetGeometryRuntimeData().skinInstance.get());
            uint64_t *skinPartPtr = (uint64_t *) (newSkinPartition.get());
            UpdateSkinPartition_object[1] = (uint64_t) skinPartPtr;
            UpdateSkinPartition_object[2] = (uint64_t) skinInstPtr;
            auto RunNIOVTaskUpdateSkinPartition = ((void (*)(uint64_t *))((uint64_t *) UpdateSkinPartition_object[0])[0]);
            RunNIOVTaskUpdateSkinPartition(UpdateSkinPartition_object);
            logger::info("new skin partition ref count after update {} {}", geo->name.c_str(), newSkinPartition->GetRefCount());
            logger::info("old skin instance ref count after update {} {}", geo->name.c_str(),
                         geo->GetGeometryRuntimeData().skinInstance->GetRefCount());
            return (RE::NiSkinPartition *) skinPartPtr;
        }
    }
    static void WalkRecalculateNormals(RE::FormID actor_id, RE::NiNode *node, std::vector<std::jthread> &spawned_threads,
                                       RecalcProgressData &progress_data) {
        if (node == nullptr) {
            return;
        }
        for (RE::NiPointer<RE::NiAVObject> obj: node->GetChildren()) {
            if (obj == nullptr) {
                continue;
            }
            if (auto c_node = obj->AsNode()) {
                WalkRecalculateNormals(actor_id, c_node, spawned_threads, progress_data);
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
                        (RE::NiRTTI *) RE::BSShaderProperty::Ni_RTTI.address())) {
                    continue;
                }
                RE::BSShaderProperty *property =
                    (RE::BSShaderProperty *) geo->GetGeometryRuntimeData().properties[RE::BSGeometry::States::kEffect].get();
                auto material = property->material;
                if (!material) {
                    continue;
                }
                if (!property->flags.all(RE::BSShaderProperty::EShaderPropertyFlag::kModelSpaceNormals)) {
                    std::lock_guard rl(recalcs_in_progress_lock);
                    progress_data.geo_queue.push(RE::NiPointer(geo));
                }
            }
        }
    }
    static uint32_t normal_delay_milliseconds = 1000;
    static void (*UpdateFaceModel)(RE::NiNode *node) = (void (*)(RE::NiNode *)) 0x0;
    static void AddActorToRecalculate(RE::Actor *actor) {
        auto handle = actor->GetHandle();
        auto original_size = 0;
        {
            std::lock_guard<std::recursive_mutex> l(queued_recalcs_mutex);
            original_size = queued_recalcs.size();
            if (queued_recalcs.contains(actor->formID)) {
                return;
            } else {
                queued_recalcs.insert_or_assign(actor->formID, handle);
            }
        }

        if (original_size == 0) {
            std::thread t([]() {
                while (true) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(normal_delay_milliseconds));
                    {
                        std::lock_guard rl(recalcs_in_progress_lock);
                        if (recalc_tasks_started == 0 && recalcs_in_progress.size() == 0) {
                            recalc_tasks_started = 1;
                            break;
                        }
                    }
                }
                SKSE::GetTaskInterface()->AddTask([]() {
                    auto processing_start_time = std::chrono::high_resolution_clock::now();
                    std::unordered_map<RE::FormID, RE::ActorHandle> temp_recalcs;
                    {
                        {
                            std::lock_guard<std::recursive_mutex> l(queued_recalcs_mutex);
                            temp_recalcs = std::unordered_map(queued_recalcs);
                            queued_recalcs.clear();
                        }
                        std::vector<std::jthread> spawned_threads1;
                        std::vector<std::jthread> spawned_threads2;
                        std::vector<std::jthread> spawned_threads3;

                        for (auto p: temp_recalcs) {
                            std::lock_guard rl(recalcs_in_progress_lock);
                            {
                                RecalcProgressData data;
                                data.actor_id = p.first;
                                data.actor_handle = p.second;
                                data.geo_queue = std::queue<RE::NiPointer<RE::BSGeometry>>();
                                recalcs_in_progress.insert_or_assign(p.first, data);
                            }
                            auto &data = recalcs_in_progress[p.first];
                            if (auto actor = p.second.get()) {
                                if (!actor->Is3DLoaded()) {
                                    actor->Load3D(false);
                                }
                                if (actor->Is3DLoaded()) {
                                    if (auto obj = actor->Get3D1(true)) {
                                        if (actor->Get3D1(true) != actor->Get3D1(false)) {
                                            if (auto node = obj->AsNode()) {
                                                WalkRecalculateNormals(p.first, node, spawned_threads1, data);
                                            }
                                        }
                                    }
                                }
                            }

                            if (auto actor = p.second.get()) {
                                if (actor->Is3DLoaded()) {
                                    if (auto obj = actor->Get3D1(false)) {
                                        if (auto node = obj->AsNode()) {
                                            WalkRecalculateNormals(p.first, node, spawned_threads2, data);
                                        }
                                    }
                                }
                            }
                            if (auto actor = p.second.get()) {
                                if (actor->Is3DLoaded()) {
                                    if (auto facenode = actor->GetFaceNodeSkinned()) {
                                        WalkRecalculateNormals(p.first, facenode, spawned_threads3, data);
                                    }
                                }
                            }
                            RE::FormID actor_id = p.first;
                            auto process_function = [](RE::FormID actor_id) {
                                std::lock_guard rl(recalcs_in_progress_lock);
                                if (!recalcs_in_progress.contains(actor_id)) {
                                    return;
                                }
                                auto &rd = recalcs_in_progress[actor_id];
                                if (auto actor = rd.actor_handle.get()) {
                                    if (auto refr = RE::TESForm::LookupByID(rd.actor_id)) {
                                        if (refr->As<RE::Actor>() != actor.get()) {
                                            recalcs_in_progress.erase(actor_id);
                                            return;
                                        }
                                    } else {
                                        recalcs_in_progress.erase(actor_id);
                                        return;
                                    }
                                    if ((actor->Is3DLoaded() == false) || actor->IsDeleted() || actor->IsDisabled()) {
                                        recalcs_in_progress.erase(actor_id);
                                        return;
                                    }
                                } else {
                                    recalcs_in_progress.erase(actor_id);
                                    return;
                                }
                                if (rd.geo_queue.empty()) {
                                    recalcs_in_progress.erase(actor_id);
                                    return;
                                } else {
                                    auto &g = rd.geo_queue.front();

                                    auto nsp = ProcessRecalcQueue(g);

                                    if (nsp) {
                                        logger::info("new skin partition ref count after return {} {}", g->name.c_str(),
                                                     nsp->GetRefCount());
                                    }
                                    rd.geo_queue.pop();
                                }
                            };
                            std::thread t([actor_id, process_function]() {
                                std::atomic_bool completed;
                                while (true) {
                                    {
                                        std::lock_guard rl(recalcs_in_progress_lock);
                                        if (!recalcs_in_progress.contains(actor_id)) {
                                            return;
                                        }
                                        auto &rd = recalcs_in_progress[actor_id];
                                        if (auto actor = rd.actor_handle.get()) {
                                            if ((actor->Is3DLoaded() == false) || actor->IsDeleted() || actor->IsDisabled()) {
                                                recalcs_in_progress.erase(actor_id);
                                                return;
                                            }
                                        }
                                    }
                                    std::this_thread::sleep_for(std::chrono::milliseconds(8));
                                    SKSE::GetTaskInterface()->AddTask([actor_id, process_function, &completed]() {
                                        process_function(actor_id);
                                        completed.store(true);
                                    });
                                    while (completed.load() != true) {
                                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                    }
                                    completed.store(false);
                                }
                            });
                            t.detach();
                        }
                    }
                    {
                        std::lock_guard rl(recalcs_in_progress_lock);
                        recalc_tasks_started = 0;
                    }
                });
            });
            t.detach();
        }
    }
    static auto OriginalFaceApplyMorph =
        (uintptr_t (*)(RE::BSFaceGenManager *, RE::BSFaceGenNiNode *, RE::TESNPC *, RE::BSFixedString *morphName, float relative)) nullptr;

    static uintptr_t FaceApplyMorphHook(RE::BSFaceGenManager *fg_m, RE::BSFaceGenNiNode *fg_node, RE::TESNPC *npc,
                                        RE::BSFixedString *morphName, float relative) {
        uintptr_t retval = OriginalFaceApplyMorph(fg_m, fg_node, npc, morphName, relative);
        if (morphName) {
            if (fg_node) {
                if (npc) {
                    auto node = fg_node;
                    if (node && GetUserDataFixed(node)) {
                        if (auto actor = GetUserDataFixed(node)->As<RE::Actor>()) {
                            if (actor->Is3DLoaded()) {
                                AddActorToRecalculate(actor);
                            }
                        }
                    }
                }
            }
        }
        return retval;
    }
    static auto SliderHook = (uintptr_t (*)(void *e, float value, uint32_t sliderId)) 0x0;
    static uintptr_t SliderHookDetour(void *e, float value, uint32_t sliderId) {
        uintptr_t retval = 0x0;
        {
            std::lock_guard<std::recursive_mutex> l(preset_mutex);
            applying_slider = true;
            retval = SliderHook(e, value, sliderId);
            applying_slider = false;
        }
        return retval;
    }
    static auto ApplyMorphsHookFaceNormalsDetour = (uintptr_t (*)(void *, RE::TESActorBase *, RE::BSFaceGenNiNode *)) 0x0;
    static uintptr_t ApplyMorphsHookFaceNormals(void *morphInterface, RE::TESActorBase *base, RE::BSFaceGenNiNode *node) {
        uintptr_t retval = 0x0;
        retval = ApplyMorphsHookFaceNormalsDetour(morphInterface, base, node);
        if (node && GetUserDataFixed(node)) {
            if (auto actor = GetUserDataFixed(node)->As<RE::Actor>()) {
                if (actor->Is3DLoaded()) {
                    AddActorToRecalculate(actor);
                }
            }
        }
        return retval;
    }
    static auto ApplyMorphHookFaceNormalsDetour = (uintptr_t (*)(void *e, RE::TESNPC *, RE::BGSHeadPart *, RE::BSFaceGenNiNode *)) 0x0;
    static uintptr_t ApplyMorphHookFaceNormals(void *morphInterface, RE::TESNPC *npc, RE::BGSHeadPart *part, RE::BSFaceGenNiNode *node) {
        uintptr_t retval = ApplyMorphHookFaceNormalsDetour(morphInterface, npc, part, node);
        if (node && GetUserDataFixed(node)) {
            if (auto actor = GetUserDataFixed(node)->As<RE::Actor>()) {
                if (actor->Is3DLoaded()) {
                    AddActorToRecalculate(actor);
                }
            }
        }
        return retval;
    }
    static auto ApplyMorphsHookBodyNormalsDetour =
        (uintptr_t (*)(void *morphInterface, RE::TESObjectREFR *refr, void *arg2, void *arg3)) nullptr;
    static uintptr_t ApplyMorphsHookBodyNormals(void *morphInterface, RE::TESObjectREFR *refr, void *arg2, void *arg3) {
        uintptr_t retval = ApplyMorphsHookBodyNormalsDetour(morphInterface, refr, arg2, arg3);
        if (refr && refr->As<RE::Actor>()) {
            AddActorToRecalculate(refr->As<RE::Actor>());
        }
        return retval;
    }
    static auto UpdateMorphsHook = (uintptr_t (*)(void *morphInterface, void *refr, void *arg3)) 0x0;
    static uintptr_t UpdateMorphsHook_fn(void *morphInterface, void *refr, void *arg3) {
        uintptr_t retval = UpdateMorphsHook(morphInterface, refr, arg3);
        if (refr) {
            if (auto actor = ((RE::TESObjectREFR *) refr)->As<RE::Actor>()) {
                if (actor->Is3DLoaded()) {
                    AddActorToRecalculate(actor);
                }
            }
        }
        return retval;
    }
    void GameEventHandler::onLoad() {
        logger::info("onLoad()");
        Hooks::install();
    }

    void GameEventHandler::onPostLoad() {
        logger::info("onPostLoad()");
    }
    class CellRecalculate : public RE::BSTEventSink<RE::TESCellFullyLoadedEvent> {
            RE::BSEventNotifyControl ProcessEvent(const RE::TESCellFullyLoadedEvent *a_event,
                                                  RE::BSTEventSource<RE::TESCellFullyLoadedEvent> *a_eventSource) {
                if (a_event && a_event->cell) {
                    a_event->cell->ForEachReference([](RE::TESObjectREFR *ref) {
                        if (auto actor = ref->As<RE::Actor>()) {
                            if (!actor->Is3DLoaded() == false) {
                                actor->Load3D(true);
                            }
                            if (RE::PlayerCharacter::GetSingleton()) {
                                AddActorToRecalculate(actor);
                            }
                        }
                        return RE::BSContainer::ForEachResult::kContinue;
                    });
                }

                return RE::BSEventNotifyControl::kContinue;
            }
    };
    class Update3DModelRecalculate : public RE::BSTEventSink<SKSE::NiNodeUpdateEvent> {
            RE::BSEventNotifyControl ProcessEvent(const SKSE::NiNodeUpdateEvent *a_event,
                                                  RE::BSTEventSource<SKSE::NiNodeUpdateEvent> *a_eventSource) {
                if (a_event && a_event->reference && a_event->reference->Is3DLoaded()) {
                    if (auto actor = a_event->reference->As<RE::Actor>()) {
                        AddActorToRecalculate(actor);
                    }
                }

                return RE::BSEventNotifyControl::kContinue;
            }
    };
    Update3DModelRecalculate *recalchook = nullptr;
    CellRecalculate *recalchook2 = nullptr;
    static std::atomic<uint32_t> skee_loaded = 0;
    void GameEventHandler::onPostPostLoad() {
        mINI::INIFile file("Data\\skse\\plugins\\skee64backports.ini");
        mINI::INIStructure ini;
        file.read(ini);
        normal_delay_milliseconds = std::stoul(ini["SKEEBackports"]["normal_delay_milliseconds"]);

        task_pool_ptr = (bool (*)(void)) REL::VariantID(38079, 39033, 0x6488a0).address();
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
                    ApplyMorphHookFaceNormalsDetour = (uintptr_t (*)(void *e, RE::TESNPC *, RE::BGSHeadPart *, RE::BSFaceGenNiNode *))(
                        (uint64_t) skee64_info.lpBaseOfDll + 0x5f480);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) ApplyMorphHookFaceNormalsDetour, &ApplyMorphHookFaceNormals);
                    DetourTransactionCommit();
                    ApplyMorphsHookFaceNormalsDetour =
                        (uintptr_t (*)(void *, RE::TESActorBase *, RE::BSFaceGenNiNode *))((uint64_t) skee64_info.lpBaseOfDll + 0x5f9e0);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) ApplyMorphsHookFaceNormalsDetour, &ApplyMorphsHookFaceNormals);
                    DetourTransactionCommit();
                    UpdateMorphsHook = (uintptr_t (*)(void *, void *, void *))((uint64_t) skee64_info.lpBaseOfDll + 0x51b0);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) UpdateMorphsHook, &UpdateMorphsHook_fn);
                    DetourTransactionCommit();
                    OriginalFaceApplyMorph = (uintptr_t (*)(RE::BSFaceGenManager *, RE::BSFaceGenNiNode *, RE::TESNPC *,
                                                       RE::BSFixedString *morphName, float relative)) REL::Offset(0x3d2220)
                                                 .address();
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) OriginalFaceApplyMorph, &FaceApplyMorphHook);
                    DetourTransactionCommit();
                    SliderHook = (uintptr_t (*)(void *e, float value, uint32_t sliderId))((uint64_t) skee64_info.lpBaseOfDll + 0x3c810);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) SliderHook, &SliderHookDetour);
                    DetourTransactionCommit();
                    ApplyMorphsHookBodyNormalsDetour = (uintptr_t (*)(void *morphInterface, RE::TESObjectREFR *refr, void *arg2,
                                                                      void *arg3))((uint64_t) skee64_info.lpBaseOfDll + 0x73d0);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) ApplyMorphsHookBodyNormalsDetour, &ApplyMorphsHookBodyNormals);
                    DetourTransactionCommit();
                    logger::info("SKEE64 1597 normal recaclulation backported");
                    if (recalchook == nullptr) {
                        recalchook = new Update3DModelRecalculate();
                        SKSE::GetNiNodeUpdateEventSource()->AddEventSink<SKSE::NiNodeUpdateEvent>(recalchook);
                        recalchook2 = new CellRecalculate();
                        RE::ScriptEventSourceHolder::GetSingleton()->AddEventSink<RE::TESCellFullyLoadedEvent>(recalchook2);
                    }
                }
                uint8_t signature1170[] = {0xff, 0x90, 0xf0, 0x03, 0x00, 0x00};
                if ((skee64_info.SizeOfImage >= 0xc2950 + 0x40) &&
                    memcmp(signature1170, (void *) ((uintptr_t) skee64_info.lpBaseOfDll + (uintptr_t) 0xc2950 + (uintptr_t) 0x28),
                           sizeof(signature1170)) == 0) {
                    UpdateFaceModel = (void (*)(RE::NiNode *)) REL::Offset(0x435c50).address();
                    NIOVTaskUpdateSkinPartitionvtable = (uint64_t) skee64_info.lpBaseOfDll + 0x1d4c60;
                    ApplyMorphHookFaceNormalsDetour = (uintptr_t (*)(void *e, RE::TESNPC *, RE::BGSHeadPart *, RE::BSFaceGenNiNode *))(
                        (uint64_t) skee64_info.lpBaseOfDll + 0xb9480);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) ApplyMorphHookFaceNormalsDetour, &ApplyMorphHookFaceNormals);
                    DetourTransactionCommit();
                    ApplyMorphsHookFaceNormalsDetour =
                        (uintptr_t (*)(void *, RE::TESActorBase *, RE::BSFaceGenNiNode *))((uint64_t) skee64_info.lpBaseOfDll + 0xb9a40);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) ApplyMorphsHookFaceNormalsDetour, &ApplyMorphsHookFaceNormals);
                    DetourTransactionCommit();
                    UpdateMorphsHook = (uintptr_t (*)(void *, void *, void *))((uint64_t) skee64_info.lpBaseOfDll + 0x167b0);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) UpdateMorphsHook, &UpdateMorphsHook_fn);
                    DetourTransactionCommit();
                    ApplyMorphsHookBodyNormalsDetour = (uintptr_t (*)(void *morphInterface, RE::TESObjectREFR *refr, void *arg2,
                                                                      void *arg3))((uint64_t) skee64_info.lpBaseOfDll + 0x1b890);
                    DetourTransactionBegin();
                    DetourUpdateThread(GetCurrentThread());
                    DetourAttach(&(PVOID &) ApplyMorphsHookBodyNormalsDetour, &ApplyMorphsHookBodyNormals);
                    DetourTransactionCommit();
                    applying_slider = false;
                    OriginalFaceApplyMorph = (uintptr_t (*)(RE::BSFaceGenManager *, RE::BSFaceGenNiNode *, RE::TESNPC *,
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
                    if (recalchook == nullptr) {
                        recalchook = new Update3DModelRecalculate();
                        SKSE::GetNiNodeUpdateEventSource()->AddEventSink<SKSE::NiNodeUpdateEvent>(recalchook);
                        recalchook2 = new CellRecalculate();
                        RE::ScriptEventSourceHolder::GetSingleton()->AddEventSink<RE::TESCellFullyLoadedEvent>(recalchook2);
                    }
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