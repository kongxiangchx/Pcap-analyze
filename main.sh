g++ -o main.out main.cc

path_input=$1
path_output=$2

if [ ! -d $path_output ];then
  mkdir $path_output
fi

files=$(ls $path_input)
for filename in $files
do
 ./main.out $path_input"/"${filename%.*}".pcap" $path_output"/"${filename%.*}".txt"
done
echo $path_input": 处理完成"