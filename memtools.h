///----------------------------------------------------------------------------------------------------
/// Copyright (c) Kevin Bieniek - Licensed under the MIT license.
///
/// Name         :  memtools.h
/// Description  :  x64 memory tools for pattern scanning, verification and navigation.
/// Authors      :  K. Bieniek
///----------------------------------------------------------------------------------------------------

#ifndef MEMTOOLS_H
#define MEMTOOLS_H

#include <windows.h>

#include <cstdint>
#include <initializer_list>
#include <psapi.h>
#include <string>
#include <vector>

#define MAX_PATTERN_LENGTH 128
#define CHAR_0             0x30 /* ascii value for '0' */
#define CHAR_9             0x39 /* ascii value for '9' */
#define CHAR_A             0x41 /* ascii value for 'A' */
#define CHAR_F             0x46 /* ascii value for 'F' */
#define HEXVAL_A           10   /* value of hex A */
#define HEXPOW_1           0x01 /* power of the first digit */
#define HEXPOW_2           0x10 /* power of the second digit */

///----------------------------------------------------------------------------------------------------
/// memtools Namespace
///----------------------------------------------------------------------------------------------------
namespace memtools
{
	///----------------------------------------------------------------------------------------------------
	/// FollowRelativeAddress:
	/// 	Follows a relative address.
	///----------------------------------------------------------------------------------------------------
	inline void* FollowRelativeAddress(void* aAddress)
	{
		int32_t jmpOffset = *(int32_t*)aAddress;

		return (PBYTE)aAddress + jmpOffset + 4;
	}

	///----------------------------------------------------------------------------------------------------
	/// Byte Struct
	///----------------------------------------------------------------------------------------------------
	struct Byte
	{
		bool    IsWildcard = false;
		uint8_t Value      = 0;
	};

	///----------------------------------------------------------------------------------------------------
	/// Pattern Struct
	///----------------------------------------------------------------------------------------------------
	struct Pattern
	{
		Byte     Bytes[MAX_PATTERN_LENGTH];
		uint64_t Size;

		constexpr Pattern() : Bytes(), Size(0) {}
		inline constexpr Pattern(const char* aPattern) : Bytes(), Size(0)
		{
			uint64_t len = 0; /* length of the pattern string */

			while (aPattern[len])
			{
				len++;
			}

			uint64_t j = 0;

			for (uint64_t i = 0; i < len; i++)
			{
				/* Pattern string not done, but already filled max byte length. */
				if (this->Size >= MAX_PATTERN_LENGTH)
				{
					break;
				}

				/* Skip spaces. */
				if (aPattern[i] == ' ') { continue; }

				/* Match wildcard. */
				if (aPattern[i] == '?')
				{
					this->Bytes[j] = Byte{ true };
					this->Size++;
					j++;

					/* Match if double wildcard '??' instead of single wildcard '?'. */
					if (i + 1 < len && aPattern[i + 1] == '?')
					{
						i++;
					}

					continue;
				}

				/* Match hex. */
				if ((aPattern[i] >= CHAR_0 && aPattern[i] <= CHAR_9) || (aPattern[i] >= CHAR_A && aPattern[i] <= CHAR_F))
				{
					uint8_t val = 0;

					/* Match if double hex 'FF' instead of single hex 'F' */
					if (i + 1 < len && (aPattern[i + 1] >= CHAR_0 && aPattern[i + 1] <= CHAR_9) || (aPattern[i + 1] >= CHAR_A && aPattern[i + 1] <= CHAR_F))
					{
						/* Calculate byte value using position.*/
						if (aPattern[i] <= CHAR_9)
						{
							val += (aPattern[i] - CHAR_0) * HEXPOW_2;
						}
						else
						{
							val += ((aPattern[i] - CHAR_A) + HEXVAL_A) * HEXPOW_2;
						}

						/* Calculate second hex value part of byte. */
						if (aPattern[i + 1] <= CHAR_9)
						{
							val += (aPattern[i + 1] - CHAR_0) * HEXPOW_1;
						}
						else
						{
							val += ((aPattern[i + 1] - CHAR_A) + HEXVAL_A) * HEXPOW_1;
						}

						i++;
					}
					else
					{
						/* Single hex value. */
						if (aPattern[i] <= CHAR_9)
						{
							val += (aPattern[i] - CHAR_0) * HEXPOW_1;
						}
						else
						{
							val += ((aPattern[i] - CHAR_A) + HEXVAL_A) * HEXPOW_1;
						}
					}

					this->Bytes[j] = Byte{ false, val };
					this->Size++;
					j++;

					continue;
				}
				else
				{
					throw "Invalid hexadecimal.";
				}
			}
		}
	};

	inline bool operator==(const Pattern& lhs, const PBYTE rhs)
	{
		for (uint64_t i = 0; i < lhs.Size; i++)
		{
			if (!lhs.Bytes[i].IsWildcard && lhs.Bytes[i].Value != rhs[i])
			{
				return false;
			}
		}

		return true;
	}

	inline bool operator==(const Pattern& lhs, const Pattern& rhs)
	{
		return memcmp(&lhs, &rhs, sizeof(Pattern)) == 0;
	}

	inline bool operator!=(const Pattern& lhs, const Pattern& rhs)
	{
		return !(lhs == rhs);
	}

	///----------------------------------------------------------------------------------------------------
	/// EOperation Enumeration
	///----------------------------------------------------------------------------------------------------
	enum class EOperation
	{
		NONE,
		offset,
		follow,
		strcmp,
		wcscmp,
		cmpi8,
		cmpi16,
		cmpi32,
		cmpi64,
		pushaddr,
		popaddr
	};

	///----------------------------------------------------------------------------------------------------
	/// Instruction Struct
	///----------------------------------------------------------------------------------------------------
	struct Instruction
	{
		EOperation       Operation;
		union
		{
			int64_t      Value;
			std::string  String;
			std::wstring WString;
		};

		Instruction() : Operation(EOperation::NONE), Value(0) {}
		Instruction(EOperation aOp, int64_t aValue) : Operation(aOp), Value(aValue) {}
		Instruction(EOperation aOp, std::string aStr) : Operation(aOp), String(aStr) {}
		Instruction(EOperation aOp, std::wstring aWStr) : Operation(aOp), WString(aWStr) {}

		inline ~Instruction()
		{
			switch (this->Operation)
			{
				case EOperation::strcmp:
				{
					this->String.~basic_string();
					break;
				}
				case EOperation::wcscmp:
				{
					this->WString.~basic_string();
					break;
				}
			}
		}

		inline Instruction(const Instruction& aOther)
		{
			this->Operation = aOther.Operation;

			switch (this->Operation)
			{
				case EOperation::strcmp:
				{
					new (&this->String) std::string(aOther.String);
					break;
				}
				case EOperation::wcscmp:
				{
					new (&this->WString) std::wstring(aOther.WString);
					break;
				}
				default:
				{
					this->Value = aOther.Value;
					break;
				}
			}
		}

		inline Instruction& operator=(const Instruction& aOther)
		{
			if (this == &aOther) { return *this; }

			this->Operation = aOther.Operation;

			switch (this->Operation)
			{
				case EOperation::strcmp:
				{
					this->String = aOther.String;
					break;
				}
				case EOperation::wcscmp:
				{
					this->WString = aOther.WString;
					break;
				}
				default:
				{
					this->Value = aOther.Value;
					break;
				}
			}

			return *this;
		}
	};

	///----------------------------------------------------------------------------------------------------
	/// DataScan Struct
	///----------------------------------------------------------------------------------------------------
	struct DataScan
	{
		Pattern                  Assembly;
		std::vector<Instruction> Instructions;

		///----------------------------------------------------------------------------------------------------
		/// ctor
		///----------------------------------------------------------------------------------------------------
		inline DataScan(const Pattern aASM, std::initializer_list<Instruction> aInstructions = {})
		{
			this->Assembly = aASM;

			for (const Instruction& instr : aInstructions)
			{
				this->Instructions.push_back(instr);
			}
		}

		///----------------------------------------------------------------------------------------------------
		/// Scan:
		/// 	Scans for the memory pattern and returns its pointer if found.
		///----------------------------------------------------------------------------------------------------
		inline void* Scan() const
		{
			if (this->Assembly.Size == 0) { return nullptr; }

			void* resultAddr = nullptr;

			MODULEINFO modInfo{};
			GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &modInfo, sizeof(modInfo));
			PBYTE addr = (PBYTE)modInfo.lpBaseOfDll;

			MEMORY_BASIC_INFORMATION mbi{};

			while (resultAddr == nullptr)
			{
				/* If virtual query fails, stop scanning. */
				if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
				{
					break;
				}

				/* If address outside of module range, stop scanning. */
				if (!(addr >= modInfo.lpBaseOfDll && addr <= (PBYTE)modInfo.lpBaseOfDll + modInfo.SizeOfImage))
				{
					break;
				}

				/* Advance query address into the next page. */
				addr += mbi.RegionSize;

				/* Sanity check: Page is smaller than bytes to match against. */
				if (this->Assembly.Size > mbi.RegionSize)
				{
					continue;
				}

				/* Skip uncommitted pages. */
				if (mbi.State != MEM_COMMIT)
				{
					continue;
				}

				/* Skip pages without read permission. */
				if (!((mbi.Protect & PAGE_READONLY) == PAGE_READONLY ||
					(mbi.Protect & PAGE_READWRITE) == PAGE_READWRITE ||
					(mbi.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
					(mbi.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE))
				{
					continue;
				}

				PBYTE base = (PBYTE)mbi.BaseAddress;
				uint64_t end = mbi.RegionSize - this->Assembly.Size; // ensure not going out of bounds

				bool isMatch = false;

				for (uint64_t i = 0; i < end; i++)
				{
					isMatch = this->Assembly == &base[i];

					if (isMatch)
					{
						resultAddr = base + i;

						uint32_t instructionsFailed = 0;

						std::vector<void*> addrStore{};

						for (const Instruction& inst : this->Instructions)
						{
							EOperation op = inst.Operation;

							switch (op)
							{
								case EOperation::offset:
								{
									resultAddr = (PBYTE)resultAddr + inst.Value;
									break;
								}
								case EOperation::follow:
								{
									resultAddr = FollowRelativeAddress((PBYTE)resultAddr + inst.Value);
									break;
								}
								case EOperation::strcmp:
								{
									instructionsFailed += strcmp((const char*)FollowRelativeAddress(resultAddr), inst.String.c_str()) == 0 ? 0 : 1;
									break;
								}
								case EOperation::wcscmp:
								{
									instructionsFailed += wcscmp((const wchar_t*)FollowRelativeAddress(resultAddr), inst.WString.c_str()) == 0 ? 0 : 1;
									break;
								}
								case EOperation::cmpi8:
								{
									instructionsFailed += *((int8_t*)resultAddr) == (int8_t)inst.Value ? 0 : 1;
									break;
								}
								case EOperation::cmpi16:
								{
									instructionsFailed += *((int16_t*)resultAddr) == (int16_t)inst.Value ? 0 : 1;
									break;
								}
								case EOperation::cmpi32:
								{
									instructionsFailed += *((int32_t*)resultAddr) == (int32_t)inst.Value ? 0 : 1;
									break;
								}
								case EOperation::cmpi64:
								{
									instructionsFailed += *((int64_t*)resultAddr) == (int64_t)inst.Value ? 0 : 1;
									break;
								}
								case EOperation::pushaddr:
								{
									addrStore.push_back(resultAddr);
									break;
								}
								case EOperation::popaddr:
								{
									resultAddr = addrStore.back();
									addrStore.pop_back();
									break;
								}
							}

							if (instructionsFailed)
							{
								/* interrupt if any failed */
								resultAddr = nullptr;
								break;
							}
						}

						if (!instructionsFailed)
						{
							/* the instructions were all executed, we interrupt the byte iteration */
							break;
						}
					}
				}
			}

			return resultAddr;
		}
	};
}

#endif
