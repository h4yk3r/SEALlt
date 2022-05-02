clear

mkdir -p build

echo "<----------BUILD PHASE START---------->"
echo ""

cmake -S . -B build -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build

echo ""
echo "<----------      FINISH     ---------->"
echo ""
