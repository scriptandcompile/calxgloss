//! String-guided algorithm hints.
//!
//! This module will provide `StringHintEngine`, which scans a decompiled
//! body and the binary's string listing against a signature database of
//! algorithm names — CRC, checksum, inflate, deflate, gzip, bz2, lzo,
//! serialize, deserialize, md5, sha, hmac, http, tcp, udp — with
//! case-insensitive matching per signature and deduplication so the same
//! algorithm is detected only once per function.
