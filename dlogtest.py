from time import clock
import math
from modules.ec import *
from modules.cryptohelp import *
from modules.dlog import *

def runDlogTest():
	alpha=random_with_bytes(1)

	primes=[millerrabin_pseudoprime_with_bytes(i, 20) for i in range(1, 10)]
	ecs=[EC(0,2,5,primes[i]) for i in range(0, 9)]
	pts=[ecs[i].pickPoint() for i in range(0, 9)]
	mults=[alpha*pts[i] for i in range(0, 9)]

	for i in range(0, 9):
		print("p = "+str(primes[i]))
		print("curve = "+str(ecs[i]))
		hw=primes[i]+1+2*math.ceil(math.sqrt(primes[i]))
		print("Running autoshanks({}, {}, {})...".format(str(pts[i]), str(mults[i]), str(hw)))

		start=clock()
		result=autoshanks(pts[i], mults[i], hw)
		end=clock()

		print("autoshanks returned {}; running time: {}".format(result, end-start))
		print("")


if __name__ == "__main__":
	runDlogTest()