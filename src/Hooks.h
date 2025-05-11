#pragma once

namespace plugin {
    class Hooks {
        public:
            static void install();

        private:
            static void quitGame();

            struct QuitGameHook {
                    static void hook() {
                        Hooks::quitGame();
                        orig();
                    }

                    static inline std::string logName = "QuitGame";
                    static inline REL::Relocation<decltype(hook)> orig;
                    static inline REL::RelocationID srcFunc = REL::RelocationID{35545, 36544};
                    static inline uint64_t srcFuncOffset = REL::Relocate(0x35, 0x1AE);

                    static void install() {
                        Hooking::writeCall<QuitGameHook>();
                    }
            };

            struct QuitGameDetoursHook {
                    static void hook() {
                        Hooks::quitGame();
                        orig();
                    }

                    static inline std::string logName = "QuitGameDetours";
                    using FuncType = decltype(&hook);
                    static inline FuncType orig;
                    static inline REL::RelocationID srcFunc = REL::RelocationID{35552, 36551};

                    static void install() {
                        // Hooking::writeDetour<QuitGameDetoursHook>();
                    }
            };
    };
}  // namespace plugin