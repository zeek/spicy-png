# @TEST-EXEC: zeek -r ${TRACES}/png.pcap %INPUT
# @TEST-EXEC: zeek -NN > zeek
# @TEST-EXEC: zeek-cut -C source depth analyzers mime_type filename total_bytes <files.log >files.log2 && mv files.log2 files.log
# @TEST-EXEC: zeek-cut -nC id <png.log >png.log2 && mv png.log2 png.log
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff png.log
#
# Spicy's #817 used to trigger a weird, make sure it doesn't come back.
# @TEST-EXEC: test '!' -f weird.log
#
# @TEST-DOC: Test PNG analyzer with an image inside a small trace.

@load analyzer
