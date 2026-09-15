/* Approximates what MSVC sees on Windows: the test client includes windows.h,
   which defines max, min and small as macros AFTER the standard headers are
   already in. Anything in the client's own code that then names std::max,
   std::min or uses "small" as an identifier breaks - and no compiler used on
   Linux notices, because windows.h is not there.
   Every header the client uses is pulled in first, so the macros below reach
   only the client's own code, exactly as they do under MSVC. */
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#define max(a,b) (((a) > (b)) ? (a) : (b))
#define min(a,b) (((a) < (b)) ? (a) : (b))
#define small char
#include "portable-token-e2e.cpp"
