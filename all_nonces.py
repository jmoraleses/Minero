import itertools as it
import numpy as np
import pandas as pd
from itertools import combinations
import tensorflow as tf
from itertools import combinations_with_replacement
from itertools import chain, combinations

def switch_h_to_int(h_char):

    if h_char == "a":
        h = 10
    elif h_char == 'b':
        h = 11
    elif h_char == 'c':
        h = 12
    elif h_char == 'd':
        h = 13
    elif h_char == 'e':
        h = 14
    elif h_char == 'f':
        h = 15
    else:
        h = int(h_char)
    return h

# def powerset(list_name):
#     s = list(list_name)
#     return chain.from_iterable(combinations(s, r) for r in range(len(s)+1))


string = "012345689abcdef012345689abcdef012345689abcdef012345689abcdef012345689abcdef012345689abcdef012345689abcdef012345689abcdef"
lista = list(string)
lista_comb = [] #np.array((1, 4))
combi = combinations_with_replacement(lista, 2)
cont = 0
for x in combi:
    serie = ["".join(str(int(x[i], 16))) for i in range(len(x))]
    lista_comb.append(serie)
    # np.append(lista_comb[cont], serie)
    cont += 1

# lista_comb = np.array(combi)

targets = np.array(lista_comb)

# tablas = np.arrays([(tf.one_hot(int(targets[i]), 16)) for i in range(len(targets))])
targ = pd.DataFrame(targets)
tablas = targ.apply( lambda y: [[np.array(tf.one_hot(int(i[a]), 16)) for a in range(len(i))] for i in y]) #.apply(lambda x: (np.array(tf.one_hot(x, 16))))
# targets = np.array([row for row in tablas])
print(tablas.shape)
tablas.to_csv("nonces.csv", index=False)