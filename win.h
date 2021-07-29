#pragma once

#include <Windows.h>

// fixme
ULONG_PTR get_mod_base(ULONG_PTR pid, const wchar_t* mod_name);
