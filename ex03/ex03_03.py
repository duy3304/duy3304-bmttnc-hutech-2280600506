def tao_tuple_tu_list(lst):
    return tuple(lst)

intput_list = input("Nhap danh sach cac so , cach nhau bang dau phay : ")
numbers = list(map(int,intput_list.split(',')))

my_tuple = tao_tuple_tu_list(numbers)
print("List:" , numbers)
print("Tuple tu List : ", my_tuple)