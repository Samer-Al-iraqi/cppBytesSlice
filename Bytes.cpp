
#include <string>
#include <cstring>
#include <string_view>
#include <vector>
#include <span>
#include <climits>
#include <cmath>
#include <stdexcept>
#include <bit>


template<typename T>
concept IsByteLike=std::is_same_v<T,char> || std::is_same_v<T,u_char>;

template<typename T>
concept normalNumber=std::integral<T> && !IsByteLike<T>;

struct Bytes;

struct BytesArray{
	Bytes *ptr;
	size_t size;
};

using BytesVector=std::vector<Bytes>;

class Bytes {
    static constexpr ulong LeadingZeros(const ulong s) { return std::countl_zero(s); }
    static constexpr ulong LeadingZeroBytes(const ulong s) { return LeadingZeros(s) / 8; }
    static constexpr ulong NonEmptyBits(const ulong s) { return sizeof(ulong) * 8 - LeadingZeros(s); }
    static constexpr ulong NonEmptyBytes(const ulong s) { return sizeof(ulong) - LeadingZeroBytes(s); }
    static constexpr size_t NextPower2(const size_t s) { return 1 << NonEmptyBits(s); }
    using byte=u_char;
    using bytePtr=u_char*;
    using constStr=const char*;
    static void throwif(const char *msg, bool cond){
        if(cond){
            throw std::runtime_error(msg);
        }
    }
    inline static const struct cBytes_t {
        static const uint c256Size = 256;
        bool CharIn(char c, std::string_view seq) { return seq.find_first_of(c) != std::string_view::npos; }
        bool alnum[c256Size];
        unsigned char toLower[c256Size];
        unsigned char toUpper[c256Size];
        const char* base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const char* base64UrlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        const char* anyBasechars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const char* hexChars = "0123456789abcdef";
        const char* hexCharsCap = "0123456789ABCDEF";
        bool hostname[c256Size];
        bool uri[c256Size];
        bool path[c256Size];
        bool query[c256Size];
        bool httpHead[c256Size];
        bool hName[c256Size];
        bool print[c256Size];
        bool *hValue = print;
        bool word[c256Size];
        bool white[c256Size];
        bool digits[c256Size];
        u_char hextoNum[c256Size];
        u_char base64ToNum[c256Size];
        u_char base64UrlToNum[c256Size];
        bool letters[c256Size];
        bool smallLetters[c256Size];
        ulong powersOf10[21];
        ulong powersOf2[65];
        ulong numStrLenByBits[65];
        cBytes_t() {
            memset(hextoNum, 255, c256Size);
            memset(base64ToNum, 255, c256Size);
            memset(base64UrlToNum, 255, c256Size);
            for (auto i = 0; i < c256Size; i++) {
                digits[i] = (i >= '0' && i <= '9');
                letters[i] = (i >= 'A' && i <= 'Z') || (i >= 'a' && i <= 'z');
                smallLetters[i] = (i >= 'a' && i <= 'z');
                alnum[i] = digits[i] || letters[i];
                hostname[i]=alnum[i] || i=='.';
                toLower[i] = (i >= 'A' && i <= 'Z') ? i + ('a' - 'A') : i;
                toUpper[i] = (i >= 'a' && i <= 'z') ? i - ('a' - 'A') : i;
                uri[i]= alnum[i] || CharIn(i, "-._~:/?#[]@!$&'()*+,;=%");
                path[i] = alnum[i] || CharIn(i, "-_.~!$'()*+,/;[]%");
                query[i] = alnum[i] || CharIn(i, "-_.~!$'()*+,;[]%=&");
                hName[i] = alnum[i] || i == '-';
                print[i] = i >= 32 && i < 127;
                httpHead[i]= (i>=32 && i<127) || i=='\n' || i=='\r';
                word[i] = alnum[i] || i == '_';
                white[i] = i == '\n' || i == '\r' || i == ' ' || i == '\t';
                {
                    auto c = strchr(hexChars, i);
                    if (c)
                        hextoNum[i] = c - hexChars;
                    else {
                        c = strchr(hexCharsCap, i);
                        if (c)
                            hextoNum[i] = c - hexCharsCap;
                    }
                }
                {
                    auto c = strchr(base64Chars, i);
                    if (c)
                        base64ToNum[i] = c - base64Chars;
                    c = strchr(base64UrlChars, i);
                    if (c)
                        base64UrlToNum[i] = c - base64UrlChars;
                }
                if (i < 65) {
                    if (i == 64)
                        powersOf2[i] = std::numeric_limits<ulong>::max();
                    else
                        powersOf2[i] = 1UL << i;
                }
                if (i < 21) {
                    if (i == 20)
                        powersOf10[i] = std::numeric_limits<ulong>::max();
                    else {
                        powersOf10[i] = 1;
                        for (auto j = 0; j < i; j++) {
                            powersOf10[i] *= 10UL;
                        }
                    }
                }
                if (i < 65) {
                    if (i == 0)
                        numStrLenByBits[i] = 1;
                    else
                        numStrLenByBits[i] = log10(powersOf2[i]) + 1;
                }
            }
        }
        constexpr size_t strNumLen(ulong n) const {
            if (n < 10)
                return 1;
            auto l = numStrLenByBits[NonEmptyBits(n)];
            return n < powersOf10[l - 1] ? l - 1 : l;
        }
    } cBytes;
    public:
	static constexpr size_t strSize(const Bytes &b) { return b.size; }
	static constexpr size_t strSize(const byte &c) { return 1; }
	static size_t strSize(const char *s) { return strlen(s); }
	static size_t strSize(const std::initializer_list<Bytes> &blist){
		size_t sz=0;
		for(auto const &b: blist){
			sz+=b.size;
		};
		return sz;
	}
	template<normalNumber numType>
	static size_t strSize(const numType n){
		if constexpr(std::is_signed_v<numType>){
			return n<0? cBytes.strNumLen(n*-1)+1 : cBytes.strNumLen(n);
		}
		else{
			return cBytes.strNumLen(n);
		}
	}

	inline static thread_local bool lastIsErr = false;
	bytePtr ptr = nullptr;
	size_t size = 0;
	Bytes() = default;

	constexpr Bytes(const void *p, const size_t len) : size(len), ptr((const bytePtr)p) {}
	Bytes(const char *p) : size(strlen(p)), ptr((bytePtr) const_cast<char *>(p)) {}
	Bytes(const std::string_view &s) : size(s.size()), ptr((bytePtr)(const_cast<char *>(s.data()))) {}
	Bytes(const std::string &s) : size(s.size()), ptr((bytePtr) const_cast<char *>(s.data())) {}
	// Bytes(Bytes&&)=delete;
	// Bytes& operator=(Bytes&&)=delete;
	// Bytes ToBytes() const { return {ptr, size}; }
	std::string_view StrView() const { return std::string_view((char *)ptr, size); }
	std::span<byte> Span() const { return std::span<byte>(ptr, size); }
	Bytes FromEnd(size_t len) const {
		throwif("Bytes::FromEnd: index or pastLen big", len > size);
		return {ptr + (size - len), len};
	}
	Bytes From(size_t index) const { return From(index, size - index); }
	Bytes From(size_t index, size_t len) const {
		throwif("Bytes::From: out of range", index > size || len + index > size);
		return Bytes(ptr + index, len);
	}
	ssize_t find(const Bytes &needle, size_t pos = 0) const {
		if (needle.size > size || pos > size - needle.size)
			return -1;
		auto p = (bytePtr)memmem(ptr + pos, size - pos, needle.ptr, needle.size);
		return p ? (p - ptr) : -1;
	}
	ssize_t find(byte needle, size_t pos = 0) const {
		if (1 > size || pos > size - 1)
			return -1;
		auto p = (bytePtr)memchr(ptr + pos, needle, size - pos);
		return p ? (p - ptr) : -1;
	}
	ssize_t rfind(const Bytes &needle, size_t pos=0) const{
		if (needle.size > size || pos > size - needle.size) return -1;
		auto const needlePtr=(char*) needle.ptr;
		return StrView().find_last_of(needlePtr, pos, needle.size);	
	}
	ssize_t rfind(const byte needle, size_t pos = 0) const{
		if(1 > size || pos > size-1) return -1;
		auto p=(bytePtr) memrchr(ptr + pos, needle, size);
		return p? p-ptr : -1;
	}
	/**
	 * len is length of substrin, from from where to get it
	 * if from is negative, then it start from that many char from the end (not start)
	 * if len is negaive, then it will get that lenth 
	*/
	Bytes substr(ssize_t from, ssize_t len) const{
		auto b=substr(from);
		if(len<0){
			len+=b.size;
			if(len<0) return {};
		}
		return len>=size? b: b.From(0,len);
	}
	Bytes substr(ssize_t from) const{
		if(from<0){
			from+=size;
			if(from<0) from=0;
		}
		return from>=size? Bytes{} : From(from);
	}
	Bytes truncateTo(size_t len) const{
		return len>size? *this: From(0,len); 
	}
	template <typename strType>
	Bytes GetUntil(const strType &needle) const {
		if constexpr(normalNumber<strType>){
			if(needle>size) return {};
			return {ptr, needle};
		}
		else{
			auto i = find(needle);
			if (i == -1) return {};
			return {ptr, (size_t)i};
		}
	}
	template <typename strType>
	Bytes GetUntil(const strType &needle, Bytes &rest) const{
		auto b=GetUntil(needle);
		size_t needleSize;
		if constexpr(normalNumber<strType>){
			needleSize=needle;
		}
		else{
			needleSize=strSize(needle);
		}
		if(!b.ptr)
			rest={ptr,size};
		else
			rest=From(b.size+needleSize);
		return b;
	}

	bool EqualTo(const Bytes &other, bool caseless=false) const {
		if(size!=other.size) return false;
		if(caseless){
			for(auto i=0;i<size;i++){
				if(cBytes.toLower[ptr[i]]!=cBytes.toLower[other.ptr[i]]) return false;
			}
			return true;
		}
		return !memcmp(ptr,other.ptr, size);
	}

	bool In(const std::initializer_list<Bytes> &these) const {
		for (const auto &one : these) {
			if (EqualTo(one))
				return true;
		}
		return false;
	}
	constStr In(const std::initializer_list<constStr> &these) const {
		for (const auto &one : these) {
			if (EqualTo(one))
				return one;
		}
		return NULL;
	}
	size_t copyFrom(const Bytes &other, bool mayOverlap = false) {
		auto min = size < other.size ? size : other.size;
		if (min) {
			if (mayOverlap)
				memmove(ptr, other.ptr, min);
		}
		(mayOverlap ? memmove : memcpy)(ptr, other.ptr, min);
		return min;
	}
	size_t copyTo(Bytes other, bool mayOverlap = false) const { return other.copyFrom(*this, mayOverlap); }
	size_t copyAllTo(bytePtr buf, bool mayOverlap = false) const{
		if(!size) return 0;
		mayOverlap?memmove(buf,ptr,size): memcpy(buf, ptr, size);
		return size;
	}
	void SetBytes(byte c = 0) { memset(ptr, c, size); }
	long ToInt(ulong max = std::numeric_limits<long>::max(), bool &err = lastIsErr) const {
		if (!size) {
			err = true;
			return 0;
		}
		if (ptr[0] == '-')
			return From(1).ToUint(max, err) * -1;
		return ToUint(max, err);
	}
	ulong ToUint(ulong max = std::numeric_limits<ulong>::max(), bool &err = lastIsErr) const {
		err = true;
		if (size > 20 || !size)
			return 0;
		ulong n = (ptr[0] - '0');
		if (n > 9)
			return 0;
		if (size == 1) {
			if (n > max)
				return 0;
			err = false;
			return n;
		}
		if (!n || cBytes.powersOf10[size - 1] > max || (size == 20 && memcmp(ptr, "18446744073709551615", 20) > 0))
			return 0;
		for (auto i = 1; i < size; i++) {
			auto c = ptr[i] - '0';
			if (c > 9)
				return 0;
			n = n * 10 + c;
		}
		if (n > max)
			return 0;
		err = false;
		return n;
	}
		// max is 20;
	static size_t FromInt(long n, bytePtr buf) {
		auto l=0;
		if (n < 0) {
			buf[l++] = '-';
			n *= -1;
		}
		l+=FromUint(n, buf+l);
		return l;
	}
	//max is 20
	static size_t FromUint(ulong n, bytePtr buf) {		
		if (n < 10) {
			buf[0] = n + '0';
			return 1;
		}
		auto l=cBytes.strNumLen(n);
		auto ret=l;
		do {
			buf[--l] = (n % 10) + '0';
			n /= 10UL;
		} while (l);
		return ret;
	}
	template<std::integral num>
	static size_t FromNum(num n, bytePtr p){
		if constexpr (std::is_signed_v<num>)
			return FromInt(n, p);
		else{
			return FromUint(n,p);
		}	
	}
	ulong hextoUint(bool &err = lastIsErr) const {
		err = true;
		if (!size || size > 16)
			return 0;
		ulong n = 0;
		for (auto i = 0; i < size; i++) {
			auto c = cBytes.hextoNum[ptr[i]];
			if (c == 255)
				return 0;
			n <<= 4;
			n |= c;
		}
		err = false;
		return n;
	}
	static constexpr size_t uintToHexLen(ulong n){
		return n<16? 1 : (16 - LeadingZeros(n) / 4);
	}
	static size_t uintToHex(ulong n, bytePtr ptr) {
		size_t size =0;
		if (n<16) {
			ptr[size++] = cBytes.hexChars[n];
			return size;
		}
		for (int i = uintToHexLen(n) - 1; i >= 0; i--) {
			ptr[size++] = cBytes.hexChars[(n >> (i * 4)) & 0xf];
		}
		return size;
	}
	// same Bytes object is allowed
	size_t constexpr hexToBinLen() const{
		return (size%2)? 0 : size/2;
	}
	size_t hexToBin(bytePtr buf, bool &err = lastIsErr) const {
		if (!size){
			err=false;
			return 0;
		}
		if (size % 2){
			err=true;
			return 0;
		}
		size_t l = 0;
		for (auto i = 0; i < size; i += 2) {
			auto c1 = cBytes.hextoNum[ptr[i]];
			auto c2 = cBytes.hextoNum[ptr[i + 1]];
			if (c1 == 255 || c2 == 255) {
				err=true;
				return 0;
			}
			buf[l++] = (c1 << 4) | c2;
		}
		err=false;
		return l;
	}
	size_t constexpr bin2HexLen() const{
		return size*2;
	}
	size_t bin2Hex(const bytePtr buf) const {
		if (!size)
			return 0;

		auto l = 0;
		for (auto i = 0; i < size; i++) {
			buf[l++] = cBytes.hexChars[ptr[i] >> 4];
			buf[l++] = cBytes.hexChars[ptr[i] & 15];
		}
		return l;
	}

	static ulong binToBase64Len(ulong binSize, bool forUrl = true) {
		auto reminder = binSize % 3;
		if (forUrl)
			return (binSize / 3) * 4 + (reminder ? reminder + 1 : 0);
		return (binSize / 3) * 4 + (reminder ? 4 : 0);
	}
	static ulong base64ToBinLen(const Bytes &base64, bool forUrl = true) {
		if(!base64) return 0;
		auto sz=(base64.size/4)*3;
		auto reminder = base64.size % 4;
		if(forUrl){
			if(reminder==1)
				return 0;
			if(!reminder)
				return sz;
			return sz+(reminder-1);
		}
		if(reminder)
			return 0;
		auto suffexLen= base64.size- base64.rTrim("=").size;
		if(!suffexLen) return sz;
		if(suffexLen>2) return 0;
		return sz-(3-suffexLen);		
	}
	size_t binTobase64(const bytePtr buf, bool forUrl = true) const {
		if (!size)
			return 0;
		auto l = 0;
		auto loopSize = (size / 3) * 3;
		struct {
			byte c1;
			byte c2;
			byte c3;
			byte c4;
		} sc;
		auto &c = (uint &)sc;
		c = 0;
		auto p = forUrl ? cBytes.base64UrlChars : cBytes.base64Chars;
		for (auto i = 0; i < loopSize; i += 3) {
			sc.c4 = ptr[i];
			sc.c3 = ptr[i + 1];
			sc.c2 = ptr[i + 2];
			buf[l++] = p[c >> 26];
			buf[l++] = p[(c << 6) >> 26];
			buf[l++] = p[(c << 12) >> 26];
			buf[l++] = p[(c << 18) >> 26];
		}
		auto reminder = size % 3;
		if (reminder) {
			c = 0;

			sc.c4 = ptr[loopSize];
			if (reminder > 1) {
				sc.c3 = ptr[loopSize + 1];
				buf[l++] = p[c >> 26];
				buf[l++] = p[(c << 6) >> 26];
				buf[l++] = p[(c << 12) >> 26];
			} else {
				buf[l++] = p[c >> 26];
				buf[l++] = p[(c << 6) >> 26];
			}
			if (!forUrl) {
				buf[l++] = '=';
				if (reminder == 1)
					buf[l++] = '=';
			}
		}
		return l;
	}
	size_t base64Tobin(bytePtr buf, bool forUrl = true, bool &err=lastIsErr) const {
		if (!size){
			err=false;
			return 0;
		}
		err=true;
			
		auto reminder = size % 4;
		auto rsize=this->size;
		if (!forUrl) {
			if (reminder)
				return 0;
			for (auto i = 1; i <= 2; i++) {
				if (last() == '=')
					rsize--;
			}
			reminder = rsize % 4;
		}
		if (reminder == 1)
			return 0;
		auto loopSize = (rsize / 4) * 4;
		size_t l=0;
		struct parts {
			byte c1;
			byte c2;
			byte c3;
			byte c4;
		} c;
		auto p = forUrl ? cBytes.base64UrlToNum : cBytes.base64ToNum;
		auto i = 0;
		for (; i < loopSize; i += 4) {
			c.c1 = p[ptr[i]];
			c.c2 = p[ptr[i + 1]];
			c.c3 = p[ptr[i + 2]];
			c.c4 = p[ptr[i + 3]];
			if (c.c1 == 255 || c.c2 == 255 || c.c3 == 255 || c.c4 == 255) {
				return 0;
			}
			buf[l++] = (c.c1 << 2) | c.c2 >> 4;
			buf[l++] = (c.c2 << 4) | c.c3 >> 2;
			buf[l++] = (c.c3 << 6) | c.c4;
		}
		if (reminder) {
			c.c1 = p[ptr[i++]];
			c.c2 = p[ptr[i++]];
			if (c.c1 == 255 || c.c2 == 255) {
				return 0;
			}
			buf[l++] = (c.c1 << 2) | c.c2 >> 4;
			if (reminder == 3) {
				c.c3 = p[ptr[i]];
				if (c.c3 == 255)
					return 0;
				buf[l++] = (c.c2 << 4) | c.c3 >> 2;
			}
		}
		err=false;
		return l;
	}
	constexpr bool IsNullPtr() const { return !ptr; }

	void ToLower() {
		for (auto i = 0; i < size; i++) {
			ptr[i] = cBytes.toLower[ptr[i]];
		}
	}
	constexpr bool empty() const { return !size; }
	byte &first() const { return ptr[0]; }
	byte &last() const { return ptr[size - 1]; }
	bool IsValidBytes(const bool *arr256Validation) const {
		for (auto i = 0; i < size; i++) {
			if (!arr256Validation[ptr[i]])
				return false;
		}
		return true;
	}
	bool StartsWith(const Bytes &needle) const { return size >= needle.size && From(0, needle.size).EqualTo(needle); }
	bool StartsWith(const byte c) const { return size >= 1 && ptr[0] == c; }
	bool EndsWith(const Bytes &needle) const { return size >= needle.size && FromEnd(needle.size).EqualTo(needle); }
	bool EndsWith(const byte c) const { return size >= 1 && ptr[size - 1] == c; }
	bool Contains(const Bytes &needle) const { return find(needle) > -1; }
	template <typename strType>
	uint CountOf(const strType &needle, uint from = 0, uint maxFind = std::numeric_limits<uint>::max()) const {
		uint cnt = 0;
		for (;;) {
			auto i = find(needle, from);
			if (i == -1 || ++cnt > maxFind)
				return cnt;
			from = i + strSize(needle);
		}
	}
	// will return number of parts ..
	template <typename strType>
	uint Split(const strType &by, Bytes *arr, size_t arrlen, bool noEmpty = false) const {
		if (!arrlen) return 0;

		if(!size){
			if(noEmpty) return 0;
			arr[0]={ptr,0};
			return 1;
		}
		auto bySize=strSize(by);

		if (!bySize) {
			auto i=0;
			while(i<arrlen-1 && i<size-1){
				arr[i]={ptr+i,1};
				i++;
			}
			if(noEmpty && !(size-i)) return i;
			arr[i]={ptr+i, size-i};
			return i+1;
		}
		auto i=0;
		Bytes b{ptr,size};
		while(i<arrlen-1){
			auto pos=b.find(by);
			if(pos==-1) break;
			auto chunk =b.From(0, pos);
			if(!noEmpty || chunk){
				arr[i++]=chunk;
			}
			b=b.From(pos+bySize);
		}
		if(!noEmpty || b)
			arr[i++]=b;
		return i;
	}
	Bytes rTrim(constStr chars="\n\r\t ") const{
		Bytes b=*this;
		while(b.size && strchr(chars, b.ptr[b.size-1])){
			b.size--;
		}
		return b;
	}
	Bytes lTrim(constStr chars="\n\r\t ") const{
		Bytes b=*this;
		while(b.size && strchr(chars, b.ptr[0])){
			b.ptr++;
			b.size--;
		}
		return b;
	}
	Bytes Trim(constStr chars="\n\r\t "){
		return rTrim(chars).lTrim(chars);
	}
	byte &operator[](int i) const { return ptr[i]; }
	operator bool() const { return size; }
	template<normalNumber numType>
	operator numType() const=delete;
	constStr cstr() const { return (char *)ptr; }
	void replaceChars(const Bytes &from, const Bytes &to) {
		if(!from || !to) return;
		auto minSize=from.size<to.size?from.size:to.size;
		auto end=ptr+size;
		for(auto i=0;i<minSize;i++){
			while(ptr<end && (ptr=static_cast<bytePtr>(memchr(ptr,from.ptr[i],end-ptr)))){
				*ptr=to.ptr[i];
				ptr++;
			}
		}
	}
	void replaceChars(byte from, byte to){
		auto end=ptr+size;
		while(ptr<end && (ptr=static_cast<bytePtr>(memchr(ptr,from,end-ptr)))){
			*ptr=to;
			ptr++;
		}
	}
};
#include <iomanip>
std::ostream &operator<<(std::ostream &out, const Bytes &s) {
	out << '"';
	for (auto i = 0; i < s.size; i++) {
		auto &c=s.ptr[i];
		if(c>=' ' && c<='~'){
			out << (char)c;
			continue;
		}
		switch(c){
			case '\n': out << "\\n\n"; continue;
			case '\t': out << "\\t"; continue;
			case '\r': out << "\\r"; continue;
		}
		out << "[\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c << ']';
	}
	out << '"';
	return out;
}

bool operator==(const Bytes &b1, const Bytes &b2) { return (b1.size == b2.size) && !memcmp(b1.ptr, b2.ptr, b1.size); }
template<typename T>
concept IsBytesLike=std::is_convertible_v<T, Bytes>;
