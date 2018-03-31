#include "packet.h"

namespace sawdust {

map<char, int> Packet::_base64;
bool Packet::_decent_char[256];
bool Packet::_is_base64_char[256];
char Packet::_iv[AES_BLOCK_SIZE];
leveldb::DB* Packet::_db;


}  // namespace sawdust
