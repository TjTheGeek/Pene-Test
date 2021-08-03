def justaddfunction(x):
    if x not in range(9):
        pass
    else:
        return x, x + 2


# if justaddfunction(9)==None:
#  print('none')

# print(justaddfunction([9,2,5]))
lol = []
for x in range(9, 11):
    lol.append(justaddfunction(x))


#noneType = True
#while noneType:
##    if None in lol:
 #       lol.remove(None)
 #   else:
 #       noneType = False
def noneType(list):  # removes every appearance of none
    noneType = True
    while noneType:
        if None in list:
            list.remove(None)
        else:
            noneType = False
    return list

print("Nonetype"+str(noneType(lol)))
print(len(lol))
for x in range(len(lol)):
    print(lol[x][0], lol[x][1])

if 'y' not in input('Would you like to exit? y/n').lower():
    intro = False