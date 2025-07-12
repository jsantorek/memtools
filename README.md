# memtools
x64 single header C++ memory tools for pattern scanning, verification and navigation.

# Usage
`#define MAX_PATTERN_LENGTH 128` is the default. Change this define as necessary.

## Patterns
Patterns are constexpr-compatible to parse at compile-time.

### Format
- Hexadecimals must be uppercase.
- Wildcards can be single `?` or double `??` question mark.
- Only hexadecimal pairs are interpreted.
- Spaces are skipped.

### Examples
Valid:
- `1A 2B ?? 4D` - Third byte is a wildcard and won't be matched.
- `1A 2B ?  4D` - Third byte is a wildcard and won't be matched.
- `1A 2B 3C 4D` - All bytes will be matched.

Invalid:
- `1a 2b 3c 4d` - Lowercase is not permitted.
- `1A2B3C4D` - Will be interpreted in pairs as `1A 2B 3C 4D`.
- `1A2B3C4` - Will be interpreted in pairs as `1A 2B 3C 04`.
- `1A 2B ??? 5E` - Will be interpreted as `1A 2B ? ? 5E`. Third and fourth byte won't be matched.

## Instructions
In addition to matching against memory patterns, you can navigate and validate around this pattern. For example, you can match against a string to confirm the address is correct.

If any instructions fail, the scanner will continue to scan to the next byte sequence that matches and perform the instructions again.
Only if the pattern matches and all instructions are successful the address will be returned.

### Operations
- `offset` - Adds an offset to the current address.
- `follow` - Follows a relative address.
- `strcmp` - Compares against an UTF8 string.
- `wcscmp` - Compares against an UTF16 string.
- `cmpi8` - Compares against an 8 bit integer.
- `cmpi16` - Compares against a 16 bit integer.
- `cmpi32` - Compares against a 32 bit integer.
- `cmpi64` - Compares against a 64 bit integer.
- `pushaddr` - Stores the current address, to return to it. E.g. to check a string in a sub function and then continue navigating the callsite.
- `popaddr` - Restores the last pushed address and continues from there.

## Examples

```cpp
/* Shorter instructions. */
using EOp = memtools::EOperation;

/* Byte pattern to search for with wildcards. */
constexpr memtools::Pattern PatternExample(
	"41 B8 ? ? ? ? "    /* Wildcards contain an irrelevant integer value, that changes often. */
	"48 8D 15 ? ? ? ? " /* Wildcards reference string "CEventHandler" */
	"48 8D 0D ? ? ? ? " /* wildcards reference string "pHandler == null" */
	"E8 ? ? ? ?"        /* Function call to a sub function, we actually want a pointer to. */
);
const memtools::DataScan ExampleScan(
	PatternExample,
	{
		{ EOp::offset, 9 },                  /* Advance 9 bytes, to the second set of wildcards. */
		{ EOp::strcmp, "CEventHandler" },    /* Compare against the expected string. */
		{ EOp::offset, 7 },                  /* Advance another 7 bytes, to the third set of wildcards. */
		{ EOp::strcmp, "pHandler == null" }, /* Compare against the expected string. */
		{ EOp::follow, 5 }                   /* Advances 5 bytes to the third set of wildcards, then follows the relative address. */
	}
);

void main()
{
	void* subfunc = ExampleScan.Scan();

	/* If the bytes matched and all actions are successful the returned pointer should be in the function called at E8 ? ? ? ?. */
}
```