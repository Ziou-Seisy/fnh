#include <cstdio>
#include <bit>
#include <thread>

#define Release 1
#define Debug 0

inline static auto swap_endian(auto x) {
	if constexpr (std::endian::native == std::endian::little) return std::byteswap(x);
	else return x;
}
inline static void FRead(auto& v, FILE* pFile) {
	fread(&v, sizeof(v), 1, pFile); v = swap_endian(v);
}

using Byte = uint8_t;
using Index = uint64_t;
using Size = uint64_t;
using B1 = uint8_t;
using B2 = uint16_t;
using B4 = uint32_t;
using B8 = uint64_t;
using B8I = int64_t;

const B4 Magic = 0x1BF52;
B1 version[3] = { 1, 0, 0 };
#if !Release
B1 argOp = 0, infoOp = 0, memOp = 0;
#endif
B8 Vp[256] = {};
enum VpTag : B1 {
	_Space = 0x00, _Len = 0x01, _CodeSp = 0x02, _DataSp = 0x03, _StackSp = 0x04,
	_ip = 0x10, _go_to = 0x11,
	_stack_base = 0x20, _stack_top = 0x21,
	_count = 0x30,
	_exp_res = 0x50, _exp_arg = 0x51, _exp_last = 0x5f,
	_error = 0xfe, _ExitWith = 0xff
};

#if !Release
void printMem(const char* str);
#endif

struct SpaceT {
	Byte* array;
	B8 size;
	SpaceT() :array(nullptr), size(0) {}
	inline bool malloc(B8 size_) {
		if (size_ == 0) return false;
		array = (Byte*)::malloc(size_);
		size = size_;
		return array != nullptr;
	}
	inline ~SpaceT() {
		if (array) {
			#if !Release
			if (memOp) printMem("Space end");
			#endif
			::free(array);
		}
		array = nullptr;
		size = 0;
	}
	inline Byte* operator+(Index index) {
		if constexpr (std::endian::native == std::endian::little) return array + (size - 1 - index);
		else return array + index;
	}
	inline Byte* pIndex(Index index, B8 size_) {
		Byte* l = *this + index;
		Byte* r = *this + (index + size_ - 1);
		return l < r ? l : r;
	}
	inline void memset(Index index, B8 size_, B1 var_ = 0) {
		::memset(pIndex(index, size_), var_, size_);
	}
	inline size_t fread(Index index, B8 size_, FILE* pFile) {
		Byte* p = pIndex(index, size_);
		size_t r = ::fread(p, 1, size_, pFile);
		if constexpr (std::endian::native == std::endian::little) {
			Byte* left = p; Byte* right = p + size_ - 1;
			while (left < right) {
				Byte temp = *left;
				*left = *right;
				*right = temp;

				++left; --right;
			}
		}
		return r;
	}
	inline B1& operator[] (Index index) { return *(*this + index); }
} Space;

template<typename Bn> inline Bn& GetN(Index index) {
	return * ( (Bn*) ( Space.pIndex(index, sizeof(Bn) ) ) );
}
template<> inline B1& GetN(Index index) { return Space[index]; }

inline void CheckStack(Index p, Size size) {
	if (p < Vp[_StackSp]) {
		#if !Release
		fprintf(stderr, "\033[31m[E]\033[0m Stack Space underflow.\n");
		#endif
		exit(0xb2);
	}
	if (p < Vp[_stack_base]) {
		#if !Release
		fprintf(stderr, "\033[31m[E]\033[0m Stack Ptr underflow.\n");
		#endif
		exit(0xb3);
	}
	if ((p + size) >= Space.size) {
		#if !Release
		fprintf(stderr, "\033[31m[E]\033[0m Stack Space overflow.\n");
		#endif
		exit(0xb4);
	}
}
inline void CheckData(Index p, Size size) {
	if ((p + size) < Space.size)return;

	#if !Release
	fprintf(stderr, "\033[31m[E]\033[0m Memory access error: Index={\033[35m%llu(0x%llx)\033[0m}\n", p, p);
	#endif
	exit(0xb1);
	
}
inline Index CheckIp(B1 add) {
	if (Vp[_ip] + add < Space.size) {
		Vp[_ip] += add;
		return Vp[_ip] - add;
	};
	#if !Release
	fprintf(stderr, "\033[31m[E]\033[0m Malformed instruction & Memory access error.\n");
	#endif
	exit(0xb5);
}
inline Index CheckSafe(Index p) {
	if ((p) < Space.size)return p;
	return 0;
}

int Main();
int Init(int argc, char** argv) {
	if (argc <= 1) {
		#if !Release
		fprintf(stderr, "\033[31m[E]\033[0m Missing input file.\n");
		#endif
		return 0xa1;
	}
	FILE* pFile = fopen(argv[1], "rb");
	if (pFile == NULL) { 
		#if !Release
		fprintf(stderr, "\033[31m[E]\033[0m File not opened: \033[36m`%s`\033[0m. ", argv[1]); perror("With"); 
		#endif
		return 0xa2; 
	}
	B4 magic; FRead(magic, pFile);
	if (Magic != magic) {
		fclose(pFile); 
		#if !Release
		fprintf(stderr, "\033[31m[E]\033[0m Invalid file format: Not a FnH file. \033[35mMagic: %u\033[0m.\n", magic);
		#endif
		return 0xa3;
	}
	fread(version, sizeof(B1), (sizeof version / sizeof B1), pFile);
	#if Release
	B1 temp1; fread(&temp1, sizeof(B1), 1, pFile);
	#else
	fread(&argOp, sizeof(B1), 1, pFile);
	infoOp = B1(argOp & B1(0b00000001)); memOp = B1(argOp & B1(0b00000010));
	if (infoOp) fprintf(stderr, "\033[32m[I]\033[0m Version: \033[33m[%u.%u.%u]\033[0m.\n\033[32m[I]\033[0m FnH file: \033[36m`%s`\033[0m.\n\033[32m[I]\033[0m Option: INFO{\033[36m%c\033[0m}.\n", version[0], version[1], version[2], argv[1], infoOp ? 'T' : 'F');
	#endif
	B8 PreSize = 16;
	B8 CodeSize; FRead(CodeSize, pFile);
	B8 DataSize; FRead(DataSize, pFile);
	B8 StackSize; FRead(StackSize, pFile);
	#if !Release
	if (infoOp) fprintf(stderr, "\033[32m[I]\033[0m Space: Pre{\033[35m%llu\033[0m+\033[36m%llu\033[0m} Code{\033[35m%llu\033[0m+\033[36m%llu\033[0m} Data{\033[35m%llu\033[0m+\033[36m%llu\033[0m} Stack{\033[35m%llu\033[0m+\033[36m%llu\033[0m}.\n", 0LL, PreSize, PreSize, CodeSize, PreSize + CodeSize, DataSize, PreSize + CodeSize + DataSize, StackSize);
	#endif
	if (!Space.malloc(PreSize + CodeSize + DataSize + StackSize)) { 
		fclose(pFile); 
		#if !Release
		fprintf(stderr, "\033[31m[E]\033[0m Memory error: malloc{%llu}. ", PreSize + CodeSize + DataSize + StackSize); perror("With"); 
		#endif
		return 0xa4;
	}
	size_t read_size = Space.fread(PreSize, CodeSize, pFile);
	fclose(pFile);
	if (read_size != CodeSize) { 
		#if !Release
		fprintf(stderr, "\033[31m[E]\033[0m Read error in \033[36m`%s`\033[0m to read {32 + \033[36m%llu\033[0m} but get {32 + \033[31m%zu\033[0m}. ", argv[1], CodeSize, read_size); if (feof(pFile))perror("With"); 
		#endif
		return 0xa5;
	}
	Space.memset(0, PreSize);
	Vp[_Space] = 0; Vp[_Len] = Space.size;
	Vp[_CodeSp] = PreSize; Vp[_DataSp] = PreSize + CodeSize;
	Vp[_StackSp] = PreSize + CodeSize + DataSize;
	Vp[_stack_base] = Vp[_StackSp]; Vp[_stack_top] = Vp[_stack_base];
	Vp[_ip] = Vp[_CodeSp];
	Vp[_ExitWith] = EXIT_SUCCESS;
	Vp[_error] = 0;
	#if !Release
	if (memOp) printMem("Space begin");
	#endif

	return 0;
}
int main(int argc, char** argv) {
	if (int r = Init(argc, argv)) return r;
	return Main();
}

using Func = void(*)(Index&);

using bcd64_t = uint64_t;
bcd64_t uint64_to_bcd64(uint64_t num) {
	bcd64_t result = 0;
	int shift = 0;

	while (num > 0 && shift < 64) {
		uint8_t digit = num % 10;
		result |= (static_cast<bcd64_t>(digit) << shift);
		num /= 10;
		shift += 4;
	}
	return result;
}
uint64_t bcd64_to_uint64(bcd64_t bcd) {
	uint64_t result = 0;
	uint64_t multiplier = 1;
	for (int i = 0; i < 16; ++i) {
		uint8_t digit = (bcd >> (i * 4)) & 0xF;
		result += digit * multiplier;
		multiplier *= 10;
	}
	return result;
}
inline void Div_(B8& r1, B8& r2, B8 a, B8 b) {
	if (b == 0) {
		#if !Release
		fprintf(stderr, "\033[31m[E]\033[0m Division by zero.\n");
		#endif
		exit(0xc2);
	}
	else r1 = a / b; r2 = a % b;
}
inline void Div_I(B8I& r1, B8I& r2, B8I a, B8I b) {
	if (b == 0) {
		#if !Release
		fprintf(stderr, "\033[31m[E]\033[0m Division by zero.\n");
		#endif
		exit(0xc2);
	}
	else r1 = a / b; r2 = a % b;
}
inline B8I& ToB8I(B8& p) {
	return (*(B8I*)&(p));
}
inline B8I uint64_to_int64(B8 val, B8 sign) {
	return (sign>0) ? B8I(val) : -B8I(val);
}
inline void int64_to_uint64(B8I x, B8& val, B8& sign) {
	if (x >= 0) {
		val = B8(x); sign = 1U;
	}
	else {
		val = B8(-x); sign = 0U;
	}
}
#if !Release
void printMem(const char* str) {
	fprintf(stderr, "\033[32m[I]\033[0m %s:\n\033[44m", str);
	for (size_t i = 0; i != Space.size; i++) {
		if (i == Vp[_CodeSp]) {
			fprintf(stderr, "\033[42m");
		}
		if (i == Vp[_DataSp]) {
			fprintf(stderr, "\033[41m");
		}
		if (i == Vp[_StackSp]) {
			fprintf(stderr, "\033[45m");
		}
		fprintf(stderr, "%02x ", Space[i]);
	}
	fprintf(stderr, "\033[0m\n");
}
#endif
#if Debug
void printMemEX(const char* str, Index last, Index to) {
	fprintf(stderr, "\033[32m[I]\033[0m %s:\n\033[44m", str);
	B8 sign = 0;
	for (size_t i = 0; i != Space.size; i++) {
		if (i == Vp[_CodeSp]) {
			sign = 42;
			fprintf(stderr, "\033[""%llu""m", sign);
		}
		if (i == Vp[_DataSp]) {
			sign = 41;
			fprintf(stderr, "\033[""%llu""m", sign);
		}
		if (i == Vp[_StackSp]) {
			sign = 45;
			fprintf(stderr, "\033[""%llu""m", sign);
		}
		if (i == last) {
			fprintf(stderr, "\033[46m");
			fprintf(stderr, "%02x ", Space[i]);
			fprintf(stderr, "\033[""%llu""m", sign);
			continue;
		}
		if (i == to) {
			fprintf(stderr, "\033[43m");
			fprintf(stderr, "%02x ", Space[i]);
			fprintf(stderr, "\033[""%llu""m", sign);
			continue;
		}
		fprintf(stderr, "%02x ", Space[i]);
	}
	if (last >= Space.size) {
		fprintf(stderr, "\033[46m");
		fprintf(stderr, "[%llu]", last);
		fprintf(stderr, "\033[""%llu""m ", sign);
	}
	if (to >= Space.size) {
		fprintf(stderr, "\033[43m");
		fprintf(stderr, "[%llu]", to);
		fprintf(stderr, "\033[""%llu""m ", sign);
	}
	fprintf(stderr, "\033[0m\nVp:\n");
	for (Index i = 0; i != 256; i++) {
		if(!(i&0xf))fprintf(stderr, "\033[41m[%llx0]", i>>4);
		fprintf(stderr, "%llu ", Vp[i]);
		fprintf(stderr, "\033[0m");
	}
	fprintf(stderr, "\033[0m\n");
}
#endif

template<typename Bn> inline void Mov() {
	Index ip = CheckIp(2); 
	B8& v = Vp[Space[ip]];
	v = Bn(Vp[Space[ip+1]]);
}
template<typename Bn> inline void Set() {
	Index ip = CheckIp(1 + sizeof (Bn));
	B8& r = Vp[Space[ip]];
	r = GetN<Bn>(ip+1);
}
template<typename Bn> inline void Get() {
	Index ip = CheckIp(2);
	B8& r = Vp[Space[ip]];
	r = (CheckData(Space[ip+1], sizeof(Bn)), GetN<Bn>(Space[ip+1]));
}
template<typename Bn> inline void Wrt() {
	Index ip = CheckIp(2);
	CheckData(Vp[Space[ip]], sizeof(Bn));
	GetN<Bn>(Vp[Space[ip]]) = (Bn)(Vp[Space[ip+1]]);
}
template<typename Bn> inline void Psh(B8 val) {
	CheckStack(Vp[_stack_top], sizeof (Bn));
	GetN<Bn>(Vp[_stack_top]) = Bn(val);
	Vp[_stack_top] += sizeof(Bn);
}
template<typename Bn> inline void Pop(B8& var) {
	Vp[_stack_top] -= sizeof (Bn);
	CheckStack(Vp[_stack_top], sizeof (Bn));
	(var) = GetN<Bn>(Vp[_stack_top]);
}
template<typename Bn> inline void XCHG(B8 ym = 0xff) {
	Index ip = CheckIp(2);
	B8& p = Vp[Space[ip]];
	Bn& x = (CheckData(Space[ip+1], sizeof(Bn)), GetN<Bn>(Space[ip+1]));
	B8 temp = x;
	x = Bn(p & ym);
	p = p & (~ym) | temp;
}
template<typename Bn> inline void SCAS() {
	Index ip = CheckIp(4);
	B8& r = Vp[Space[ip]];
	Bn x = Bn(Vp[Space[ip+1]]);
	Index a = Vp[Space[ip+2]];
	Size si = Vp[Space[ip+3]];
	for (Index i = 0; i != si; i++) {
		if (Space[a + i] == x) {
			r = i; return;
		}
	}
	r = B8(-1);
}

inline B8 Than_(B8 a, B8 b) {
	return a > b ? 1 : (a < b ? B8(-1) : 0);
}
inline B8I Than_I(B8I a, B8I b) {
	return a > b ? 1 : (a < b ? -1 : 0);
}
inline void MOVS_() {
	Index ip = CheckIp(3);
	Index f = Vp[Space[ip]];
	Index t = Vp[Space[ip+1]];
	Size si = Vp[Space[ip+2]];
	for (Index i = 0; i != si; i++) {
		Space[t + i] = Space[f + i];
	}
}
inline void CMPS_() {
	Index ip = CheckIp(4);
	B8& r = Vp[Space[ip]];
	Index a = Vp[Space[ip+1]];
	Index b = Vp[Space[ip+2]];
	Size si = Vp[Space[ip+3]];
	for (Index i = 0; i != si; i++) {
		if(Space[a + i] == Space[b + i])continue;
		r = Space[a + i] < Space[b + i] ? B8(-1) : 1U; return;
	}
	r = 0;
}
inline void fopen_(B8& file, Index path, Size pathLen, Index mod, Size modLen) {
	CheckData(path, pathLen);
	char* pathStr = (char*)Space.pIndex(path, pathLen);
	CheckData(mod, modLen);
	char* modStr = (char*)Space.pIndex(mod, modLen);
	Vp[_error] = B8(fopen_s((FILE**) & file, pathStr, modStr));
}
inline void fin_(B8 file, Index sp, Size spLen, Size once, Size cnt, B8& r) {
	CheckData(sp, spLen);
	char* pStr = new char[spLen] {};
	FILE* pFile;
	switch (file) {
		case 0: pFile = stderr; break;
		case 1: pFile = stdin; break;
		case 2: pFile = stdout; break;
		default:pFile = *(FILE**)&file;
	}
	r = fread_s(pStr, spLen, once, cnt, pFile);
	for (Index i = 0; i != spLen; i++)Space[sp + i] = B1(pStr[i]);
}
inline void fout_(B8 file, Index sp, Size spLen, Size once, Size cnt, B8& r) {
	CheckData(sp, spLen);
	if (once * cnt > spLen) { 
		r = 0; 
		//fprintf(stderr, "[E] out: \"%s\"(%llu) [%llu] {%llu*%llu} -> ?(%llx) Ret %llu.\n", spLen, once, cnt, file, r);
		return; 
	}
	char* pStr = new char[spLen] {};
	for (Index i = 0; i != spLen; i++)pStr[i] = char(Space[sp + i]);
	FILE* pFile;
	switch (file) {
		case 0: pFile = stderr; break;
		case 1: pFile = stdin; break;
		case 2: pFile = stdout; break;
		default:pFile = *(FILE**)&file;
	}
	r = fwrite(pStr, once, cnt, pFile);
	//fprintf(stderr, "[I] out: %s [%llu] {%llu*%llu} -> %llx(%llx) Ret %llu.\n", pStr, spLen, once, cnt, (B8)pFile, file, r);
	delete[] pStr;
}

enum FuncTag {
	NOP = 0x00, Exit = 0x01, Goto = 0x02, IfGo = 0x03, IfNG = 0x04, SvIp = 0x05, Loop = 0x06,
	Call = 0x08, Ret = 0x09, 

	Add = 0x10, Sub = 0x11, Mul = 0x12, Div = 0x13, Inc = 0x14, Dec = 0x15, 
	Than = 0x16, Less = 0x17, More = 0x18, Not = 0x19, And = 0x1a, Or = 0x1b, Xor = 0x1c, ToBool = 0x1d,

	Mov1 = 0x20, Mov2 = 0x21, Mov4 = 0x22, Mov8 = 0x23,
	Set1 = 0x28, Set2 = 0x29, Set4 = 0x2a, Set8 = 0x2b,
	Get1 = 0x30, Get2 = 0x31, Get4 = 0x32, Get8 = 0x33, LEA = 0x37,
	Wrt1 = 0x38, Wrt2 = 0x39, Wrt4 = 0x3a, Wrt8 = 0x3b,
	Psh1 = 0x40, Psh2 = 0x41, Psh4 = 0x42, Psh8 = 0x43,
	Pop1 = 0x48, Pop2 = 0x49, Pop4 = 0x4a, Pop8 = 0x4b,

	XCHG1 = 0x50, XCHG2 = 0x51, XCHG4 = 0x52, XCHG8 = 0x53, Swap = 0x57,

	BcdT = 0x60, BcdF = 0x61, SignT = 0x62, SignF = 0x63, LMov = 0x64, RMov = 0x65, ROL = 0x66, ROR = 0x67,
	Complement = 0x68, IMul = 0x69, IDiv = 0x6a, IThan = 0x6b, ILess = 0x6c, IMore = 0x6d, ILMov = 0x6e, IRMov = 0x6f,

	‌MOVS = 0x70, CMPS = 0x71, Data = 0x72,
	‌SCAS‌1 = 0x78, SCAS‌2 = 0x79, SCAS‌4 = 0x7a, SCAS8 = 0x7b,

	FOPEN = 0x80, FIN = 0x81, FOUT = 0x82,

	HTL = 0xe0,
};

int Main() {
	auto& ip__ = Vp[_ip];
	#if !Release
	FuncTag lastFuncID = FuncTag(0); B8 lastIp = 0;
	#endif
	while (ip__ < Vp[_Len]) {
		#if !Release
		lastIp = ip__;
		#endif
		Index ip = CheckIp(1); FuncTag func_id = FuncTag(Space[ip]);
		#if !Release
		lastFuncID = func_id;
		#endif
		switch (func_id) {
			case NOP:break;
			case Exit:return int(Vp[_ExitWith]);
			case Goto:ip = CheckIp(1); Vp[_ip] = Vp[Space[ip+1]]; break;
			case IfGo:ip = CheckIp(2); if(Vp[Space[ip]]) Vp[_ip] = Vp[Space[ip+1]]; break;
			case IfNG:ip = CheckIp(2); if(!(Vp[Space[ip]])) Vp[_ip] = Vp[Space[ip+1]]; break;
			case SvIp:ip = CheckIp(1); Vp[Space[ip]] = Vp[_ip]; break;
			case Loop:ip = CheckIp(2); if (--(Vp[Space[ip]])) Vp[_ip] = Vp[Space[ip+1]]; break;
			case Call:ip = CheckIp(1); Psh<B8>(Vp[_ip]); Vp[_ip] = Vp[Space[ip + 1]]; break;
			case Ret:ip = CheckIp(0); Pop<B8>(Vp[_ip]); break;
			case Add:ip = CheckIp(3); Vp[Space[ip]] = Vp[Space[ip + 1]] + Vp[Space[ip + 2]]; ip += 3; break;
			case Sub:ip = CheckIp(3); Vp[Space[ip]] = Vp[Space[ip+1]] - Vp[Space[ip+2]]; break;
			case Mul:ip = CheckIp(3); Vp[Space[ip]] = Vp[Space[ip+1]] * Vp[Space[ip+2]]; break;
			case Div:ip = CheckIp(4); Div_(Vp[Space[ip]], Vp[Space[ip+1]], Vp[Space[ip+2]], Vp[Space[ip+3]]); break;
			case IMul:ip = CheckIp(3); ToB8I(Vp[Space[ip]]) = ToB8I(Vp[Space[ip+1]]) * ToB8I(Vp[Space[ip+2]]); break;
			case IDiv:ip = CheckIp(4); Div_I(ToB8I(Vp[Space[ip]]), ToB8I(Vp[Space[ip+1]]), ToB8I(Vp[Space[ip+2]]), ToB8I(Vp[Space[ip+3]])); break;
			case Inc:ip = CheckIp(1); ++Vp[Space[ip]]; break;
			case Dec:ip = CheckIp(1); --Vp[Space[ip]]; break;
			case Than:ip = CheckIp(3); Vp[Space[ip]] = Than_(Vp[Space[ip+1]] , Vp[Space[ip+2]]); break;
			case Less:ip = CheckIp(3); Vp[Space[ip]] = Vp[Space[ip+1]] < Vp[Space[ip+2]]; break;
			case More:ip = CheckIp(3); Vp[Space[ip]] = Vp[Space[ip+1]] > Vp[Space[ip+2]]; break;
			case IThan:ip = CheckIp(3); ToB8I(Vp[Space[ip+1]]) = Than_I(ToB8I(Vp[Space[ip+2]]), ToB8I(Vp[Space[ip+3]])); break;
			case ILess:ip = CheckIp(3); ToB8I(Vp[Space[ip+1]]) = ToB8I(Vp[Space[ip+2]]) < ToB8I(Vp[Space[ip+3]]); break;
			case IMore:ip = CheckIp(3); ToB8I(Vp[Space[ip+1]]) = ToB8I(Vp[Space[ip+2]]) > ToB8I(Vp[Space[ip+3]]); break;
			case Not:ip = CheckIp(2); if (Vp[Space[ip + 1]]) Vp[Space[ip]] = 0U; else Vp[Space[ip]] = 1U; break;
			case And:ip = CheckIp(3); Vp[Space[ip]] = Vp[Space[ip+1]] & Vp[Space[ip+2]]; break;
			case Or:ip = CheckIp(3); Vp[Space[ip]] = Vp[Space[ip+1]] | Vp[Space[ip+2]]; break;
			case Xor:ip = CheckIp(3); Vp[Space[ip]] = Vp[Space[ip+1]] ^ Vp[Space[ip+2]]; break;
			case LMov:ip = CheckIp(3); Vp[Space[ip]] = Vp[Space[ip+1]] << Vp[Space[ip+2]]; break;
			case RMov:ip = CheckIp(3); Vp[Space[ip]] = Vp[Space[ip+1]] >> Vp[Space[ip+2]]; break;
			case ILMov:ip = CheckIp(3); ToB8I(Vp[Space[ip]]) = ToB8I(Vp[Space[ip+1]]) << ToB8I(Vp[Space[ip+2]]); break;
			case IRMov:ip = CheckIp(3); ToB8I(Vp[Space[ip]]) = ToB8I(Vp[Space[ip+1]]) >> ToB8I(Vp[Space[ip+2]]); break;
			case ROL:ip = CheckIp(3); Vp[Space[ip]] = std::rotl(Vp[Space[ip+1]], (int)ToB8I(Vp[Space[ip+2]])); break;
			case ROR:ip = CheckIp(3); Vp[Space[ip]] = std::rotr(Vp[Space[ip+1]], (int)ToB8I(Vp[Space[ip+2]])); break;
			case ToBool:ip = CheckIp(2); if (Vp[Space[ip + 1]]) Vp[Space[ip]] = 1U; else Vp[Space[ip]] = 0U; break;
			case Complement: ip = CheckIp(2); Vp[Space[ip]] = ~(Vp[Space[ip+1]]); break;
			case HTL:std::this_thread::sleep_for(std::chrono::hours(1)); break;
			case Swap:ip = CheckIp(2); std::swap(Vp[Space[ip]],Vp[Space[ip+1]]); break;
			case Mov1:Mov<B1>(); break;
			case Mov2:Mov<B2>(); break;
			case Mov4:Mov<B4>(); break;
			case Mov8:Mov<B8>(); break;
			case Set1:Set<B1>(); break;
			case Set2:Set<B2>(); break;
			case Set4:Set<B4>(); break;
			case Set8:Set<B8>(); break;
			case Get1:Get<B1>(); break;
			case Get2:Get<B2>(); break;
			case Get4:Get<B4>(); break;
			case Get8:Get<B8>(); break;
			case Wrt1:Wrt<B1>(); break;
			case Wrt2:Wrt<B2>(); break;
			case Wrt4:Wrt<B4>(); break;
			case Wrt8:Wrt<B8>(); break;
			case Psh1:ip = CheckIp(1); Psh<B1>(Vp[Space[ip]]); break;
			case Psh2:ip = CheckIp(1); Psh<B2>(Vp[Space[ip]]); break;
			case Psh4:ip = CheckIp(1); Psh<B4>(Vp[Space[ip]]); break;
			case Psh8:ip = CheckIp(1); Psh<B8>(Vp[Space[ip]]); break;
			case Pop1:ip = CheckIp(1); Pop<B1>(Vp[Space[ip]]); break;
			case Pop2:ip = CheckIp(1); Pop<B2>(Vp[Space[ip]]); break;
			case Pop4:ip = CheckIp(1); Pop<B4>(Vp[Space[ip]]); break;
			case Pop8:ip = CheckIp(1); Pop<B8>(Vp[Space[ip]]); break;
			case BcdF:ip = CheckIp(2); Vp[Space[ip]] = uint64_to_bcd64(Vp[Space[ip+1]]); break;
			case BcdT:ip = CheckIp(2); Vp[Space[ip]] = bcd64_to_uint64(Vp[Space[ip+1]]); break;
			case SignF:ip = CheckIp(3); ToB8I(Vp[Space[ip]]) = uint64_to_int64(Vp[Space[ip+1]], Vp[Space[ip+2]]); break;
			case SignT:ip = CheckIp(3); int64_to_uint64(ToB8I(Vp[Space[ip]]), Vp[Space[ip+1]], Vp[Space[ip+2]]); break;
			case LEA:ip = CheckIp(4); Vp[Space[ip]] = CheckSafe(Vp[Space[ip+1]] + (Vp[Space[ip+2]] * Vp[Space[ip+3]])); break;
			case XCHG1:XCHG<B1>(0xff); break;
			case XCHG2:XCHG<B2>(0xffff); break;
			case XCHG4:XCHG<B4>(0xffffffff); break;
			case XCHG8:XCHG<B8>(0xffffffffffffffff); break;
			case ‌MOVS: MOVS_(); break;
			case CMPS: CMPS_(); break;
			case ‌SCAS‌1: SCAS<B1>(); break;
			case SCAS‌2: SCAS<B2>(); break;
			case SCAS‌4: SCAS<B4>(); break;
			case SCAS8: SCAS<B8>(); break;
			case FOPEN: ip = CheckIp(5); fopen_(Vp[Space[ip]], Vp[Space[ip+1]], Vp[Space[ip+2]], Vp[Space[ip+3]], Vp[Space[ip+4]]); break;
			case FIN: ip = CheckIp(6); fin_(Vp[Space[ip]], Vp[Space[ip+1]], Vp[Space[ip+2]], Vp[Space[ip+3]], Vp[Space[ip+4]], Vp[Space[ip+5]]); break;
			case FOUT: ip = CheckIp(6); fout_(Vp[Space[ip]], Vp[Space[ip+1]], Vp[Space[ip+2]], Vp[Space[ip+3]], Vp[Space[ip+4]], Vp[Space[ip+5]]); break;
			case Data: { ip = CheckIp(1); B8& vpi = Vp[Space[ip]]; Vp[_ip]--; Set<B8>(); B8 at = Vp[_ip]; Vp[_ip]--/*Why??*/; Vp[_ip] += vpi; vpi = at; }break;
			default:
			{
				#if !Release
				fprintf(stderr, "\033[31m[E]\033[0m No instruction: id={\033[33m0x%02x\033[0m} at={\033[35m%llu(0x%llx)\033[0m}.\n", func_id, Vp[_ip], ip);
				#endif
				#if !Release
				if (infoOp) fprintf(stderr, "\033[32m[I]\033[0m Last instruction: id={\033[33m0x%02x\033[0m} at={\033[35m%llu(0x%llx)\033[0m}.\n", lastFuncID, lastIp, lastIp);
				#endif
				return 0xc1;
			}
		}
		
		#if Debug
		if (infoOp) fprintf(stderr, "\033[32m[I]\033[0m When: %llu 0x%llx.\n", lastIp, (B8)lastFuncID);
		if (memOp) printMemEX("Space Now", lastIp, Vp[_ip]);
		system("pause");
		#endif
	}

	#if !Release
	if (infoOp) fprintf(stderr, "\033[32m[I]\033[0m Exit: %llu (0x%llx).\n", Vp[_ExitWith], Vp[_ExitWith]);
	#endif

	return int(Vp[_ExitWith]);
}