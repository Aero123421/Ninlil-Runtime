/*
 * Installed-package smoke: link the production factory header/archive only.
 * Uses supported diagnostics (no private pure helpers).
 */
#include "ninlil_posix_sqlite_storage.h"

int main(void)
{
    if (ninlil_posix_sqlite_storage_live_handles(NULL) != 0u) {
        return 1;
    }
    if (ninlil_posix_sqlite_storage_connection_fenced(NULL) != 0) {
        return 1;
    }
    return 0;
}
