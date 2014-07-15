set logscale y 10
#set format x "%.0f"
#set format x "%.0f"
set key right bottom

#set xtics ("6" 6, "7" 7, "8" 8, "9" 9, "10" 10)
set xtics ("6" 6, "7" 7, "8" 8, "9" 9, "10" 10, "11" 11, "12" 12)
set ytics ("1 minute" 60, "1 hour" 3600, "1 day" 86400, "1 year" 31557600, "1000 years" 3.15576e10, "1 million years" 3.15576e13, "1 billion years" 3.15576e16, "1 trillion years" 3.1557e19) 

#set format x "10^{%L}"
#set format y "10^{%L}"

#set xrange [6:10]
set xrange [6:12]
set yrange [60:3.15576e19]
set xlabel "Password Length"
set ylabel "CPU Time w/ 1 billion \n guesses per second" offset 4
set size 1.0,1.0

set style line 100 linetype -1 lw 0.8 linecolor rgb "#DADADA"
set grid linestyle 100


set style line 1 lw 3
set style line 2 lw 3
set style line 3 lw 3
set style line 4 lw 3

set terminal postscript enhanced color 20
set output "plotcrack.eps"
plot "crack.dat" using 1:2 title 'Salted Hash' with linespoints ls 1 lw 6 ps 3, \
 "crack.dat" using 1:3 title 'PolyPasswordHasher k=2' with linespoints ls 2 lw 6 ps 3, \
 "crack.dat" using 1:4 title 'PolyPasswordHasher k=3' with linespoints ls 3 lw 6 ps 3, \
 "crack.dat" using 1:5 title 'PolyPasswordHasher partial k=2' with linespoints ls 4 lw 6 ps 3, \
 "crack.dat" using 1:6 title 'PolyPasswordHasher partial k=3' with linespoints ls 5 lw 6 ps 3
