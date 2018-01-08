xcrun -sdk iphoneos clang -arch arm64 *.m *.c -I. -o jailbreakd -framework Foundation -framework IOKit
jtool --sign --inplace --ent Ent.plist jailbreakd
