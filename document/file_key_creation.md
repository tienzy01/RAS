// pseudo

sprintf(key, "%05i", dirId);
strncat(key, fileName, ...);

// code

std::snprintf(prefix, sizeof(prefix), "%05i", static_cast<int>(dirId));
key += prefix;
key += fileName;