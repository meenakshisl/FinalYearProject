package main

import "fmt"

import "miracl/core/go/core"
import "miracl/core/go/core/BN254"

func FP12toByte(F *BN254.FP12) []byte {

	const MFS int = int(BN254.MODBYTES)
	var t [12 * MFS]byte

	F.ToBytes(t[:])
	return(t[:])
}

func main() {
    rng := core.NewRAND()
    var raw [100]byte
    for i := 0; i < 100; i++ {
    raw[i] = byte(i + 1)
    }
    rng.Seed(100, raw[:])


	mymsg:="hello"
	msg:=[]byte(mymsg)

	sh:=core.NewHASH256()
	for i:=0;i<len(msg);i++ {
		sh.Process(msg[i])
	}
	m1:=BN254.FromBytes(sh.Hash())

	msg=[]byte("Hello")

	sh=core.NewHASH256()
	for i:=0;i<len(msg);i++ {
		sh.Process(msg[i])
	}
	m2:=BN254.FromBytes(sh.Hash())


    	p := BN254.NewBIGints(BN254.Modulus)
    	q := BN254.NewBIGints(BN254.CURVE_Order)

    	x := BN254.Randomnum(q,rng) // Generate a random number less than q
    	y1 := BN254.Randomnum(q,rng)
    	y2 := BN254.Randomnum(q,rng)

    	G2:= BN254.ECP2_generator() // Generator point in G2

    	h := BN254.Randomnum(p,rng) // Create random point on curve
    	H := BN254.ECP_hashit(h) 


    	X := BN254.G2mul(G2,x)
	Y1 := BN254.G2mul(G2,y1)
	Y2 := BN254.G2mul(G2,y2)
	e1 := BN254.Modmul(y1,m1,q); 
	e2 := BN254.Modmul(y2,m2,q);
	e := BN254.Modadd(e1,e2,q);
	e = BN254.Modadd(e,x,q) // (x+y1.m2 + y2.m2) mod q

	sig1 := BN254.NewECP(); sig1.Copy(H)
	sig2 := BN254.G1mul(H,e)

	X.Add(BN254.G2mul(Y1,m1))
	X.Add(BN254.G2mul(Y2,m2))

	LHS:=BN254.Ate(X,sig1);  LHS=BN254.Fexp(LHS)
	RHS:=BN254.Ate(G2,sig2); RHS=BN254.Fexp(RHS)
	fmt.Printf("Message: %s\n",mymsg);

        fmt.Printf("Private key:\tx=%s, y=%s\n",x.ToString(),y1.ToString())
        fmt.Printf("Random value (h):\th=%s\n\n",h.ToString())

        fmt.Printf("Public key:\ng2=%s\nX=%s\nY1=%s\nY2=%s\n\n",G2.ToString(),X.ToString(),Y1.ToString(),Y2.ToString())

        fmt.Printf("Sig1=%s\nSig2=%s\n\n",sig1.ToString(),sig2.ToString())
        fmt.Printf("Pair 1 - first 20 bytes:\t0x%x\n",FP12toByte(LHS)[:20])
        fmt.Printf("Pair 2 - first 20 bytes:\t0x%x\n",FP12toByte(RHS)[:20])

	if LHS.Equals(RHS) { fmt.Printf("\nSignatures match\n")}
}
