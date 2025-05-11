#include "Hooks.h"
namespace plugin {
    void Hooks::install() {
        QuitGameHook::install();
    }

    void Hooks::quitGame() {
        logger::info("Game quitting");
    }
}  // namespace plugin
