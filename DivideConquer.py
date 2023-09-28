import math


def percentage(number):
    return number / 100


def get_int(prompt):
    try:
        i = int(input(prompt))
        return i
    except ValueError:
        print("Please enter an integer.")
        return get_int(prompt)


def get_centi(prompt):
    i = get_int(prompt)
    if i < 0 or i > 100:
        print("Please enter an integer not less than 0 and not greater than 100.")
        return get_centi(prompt)
    return i


def div_con(dgsb):
    if len(dgsb) == 0:
        return 0
    if len(dgsb) == 1:
        return percentage(dgsb[0])
    
    half = len(dgsb) // 2
    
    k = dgsb[:half]
    l = dgsb[half:]
        
    return div_con(k) + div_con(l)
    
    
def main():
    dgsb = []
    
    dgsb.append(get_centi("Demographics: "))
    dgsb.append(get_centi("Geography: "))
    dgsb.append(get_centi("Socio-economics: "))
    dgsb.append(get_centi("Behavioral qualities: "))
    
    v = get_int("Governor: ")
    i = math.ceil((div_con(dgsb) / 4) * v)
    print(f"Number of regions: {i}")


if __name__ == "__main__":
    main()
