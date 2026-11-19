#include "KDechunkEngine.h"
#include "KHttpValidation.h"

static bool chunk_line(const std::string& line, uint32_t& size) {
	size_t i = 0;
	size = 0;
	while (i < line.size()) {
		unsigned char c = (unsigned char)line[i];
		int digit = c >= '0' && c <= '9' ? c - '0' :
			(c >= 'a' && c <= 'f' ? c - 'a' + 10 : (c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1));
		if (digit < 0) break;
		if (size > (KHTTPD_MAX_CHUNK_SIZE - digit) / 16) return false;
		size = size * 16 + digit;
		++i;
	}
	if (i == 0) return false;
	while (i < line.size()) {
		while (i < line.size() && (line[i]==' ' || line[i]=='\t')) ++i;
		if (i == line.size() || line[i++] != ';') return false;
		while (i < line.size() && (line[i]==' ' || line[i]=='\t')) ++i;
		size_t start = i;
		while (i < line.size() && khttp_is_token((unsigned char)line[i])) ++i;
		if (start == i) return false;
		while (i < line.size() && (line[i]==' ' || line[i]=='\t')) ++i;
		if (i < line.size() && line[i]=='=') {
			++i;
			while (i < line.size() && (line[i]==' ' || line[i]=='\t')) ++i;
			if (i < line.size() && line[i]=='"') {
				++i;
				bool closed = false;
				while (i < line.size()) {
					unsigned char c = (unsigned char)line[i++];
					if (c=='"') { closed=true; break; }
					if (c=='\\') {
						if (i == line.size()) return false;
						c=(unsigned char)line[i++];
					}
					if ((c < 32 && c != '\t') || c==127) return false;
				}
				if (!closed) return false;
			} else {
				start=i;
				while (i < line.size() && khttp_is_token((unsigned char)line[i])) ++i;
				if (start==i) return false;
			}
		}
	}
	return true;
}
KDechunkResult KDechunkEngine::dechunk(const char** buf, const char* end, const char** piece, int* piece_length) {
	const char* start = *buf;
	KDechunkResult result = dechunk_internal(buf, end, piece, piece_length);
	received += *buf - start;
	if (result == KDechunkResult::Success) {
		data_received += *piece_length;
	}
	if (result != KDechunkResult::End && result != KDechunkResult::Failed &&
		received / 8 > data_received + KHTTPD_MAX_CHUNK_OVERHEAD) {
		state = Failed;
		return KDechunkResult::Failed;
	}
	return result;
}
KDechunkResult KDechunkEngine::dechunk_internal(const char** buf, const char* end, const char** piece, int* piece_length) {
	if (state==End) return KDechunkResult::End;
	if (state==Failed || *piece_length <= 0) return KDechunkResult::Failed;
	// Trailers own their storage, so a line can span any number of network reads.
	if (state==Trailer && !line.empty() && !line_cr && line.back()=='\n') line.clear();
	while (*buf < end) {
		if (state==Data) {
			int n = KGL_MIN(*piece_length, (int)KGL_MIN((size_t)chunk_size, (size_t)(end-*buf)));
			*piece = *buf; *piece_length=n; *buf+=n; chunk_size-=n;
			if (!chunk_size) state=DataCR;
			return KDechunkResult::Success;
		}
		char c = *(*buf)++;
		if (state==DataCR || state==DataLF) {
			if (c != (state==DataCR ? '\r' : '\n')) goto failed;
			state = state==DataCR ? DataLF : Size;
			continue;
		}
		if (!line_cr) {
			if (c=='\r') { line_cr=true; continue; }
			if (c=='\n' || c==0 || line.size() >= KHTTPD_MAX_TRAILER_LINE) goto failed;
			line.push_back(c);
			continue;
		}
		line_cr=false;
		if (c!='\n') goto failed;
		if (state==Size) {
			if (!chunk_line(line, chunk_size)) goto failed;
			line.clear();
			state = chunk_size ? Data : Trailer;
			continue;
		}
		if (line.empty()) { state=End; return KDechunkResult::End; }
		if (++trailer_count > KHTTPD_MAX_TRAILER_COUNT) goto failed;
		{
			size_t sep=line.find(':');
			if (sep==std::string::npos || !khttp_valid_trailer(line.data(), (int)sep, line.data()+sep+1, (int)(line.size()-sep-1))) goto failed;
			*piece_length=(int)line.size();
			line.push_back('\n'); // Marker excluded from the returned field length.
			*piece=line.data();
			return KDechunkResult::Trailer;
		}
	}
	return KDechunkResult::Continue;
failed:
	state=Failed;
	return KDechunkResult::Failed;
}
