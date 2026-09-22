filename\0
uint32 logicalSize
uint32 storedSize
uint32 unknown2
uint32 directoryId
int32  fileSeed
uint32 method
16-byte timestamp

// code

f.logicalSize = le32(rec + 0);
f.storedSize  = le32(rec + 4);
f.unknown2    = le32(rec + 8);
f.dirId       = le32(rec + 12);
f.seed        = static_cast<std::int32_t>(le32(rec + 16));
f.method      = le32(rec + 20);
f.timestamp   = readTimestamp(rec + 24);