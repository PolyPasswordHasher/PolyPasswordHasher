set logscale x 2
set logscale y 10
set format x "%.0f"
set key at 80,8
#set key top left
set object rect from .95,10 to 55,.06

set xtics ("1" 1, "2" 2, "4" 4, "8" 8, "16" 16, "32" 32, "64" 64, "128" 128, "256" 256) 

set ytics ("10s" 10, "1s" 1, "100ms" .1, "10ms" .01, "1ms" .001, "100{/Symbol m}s" .0001, "10{/Symbol m}s" .00001) 


set xrange [.8:300]
set yrange [.00001:10]
set xlabel "Threshold Value"
set ylabel "Time"
set size 0.6,0.6


set terminal postscript enhanced color solid
set output "onebigtimegraph.eps"
plot "mac.auth" using ($1):($2) title 'Authenticate Threshold' lw 4 ps 2, "mac.thresholdless.auth" using ($1):($2) title 'Authenticate Thresholdless' lw 4 ps 2, "mac.create" using ($1):($2) title 'Create Threshold Account' lw 4 ps 2, "mac.thresholdless.create" using ($1):($2) title 'Create Thresholdless Account' lw 4 ps 2, "mac.init" using ($1):($2) title 'Initialize Store' lw 4 ps 2, "mac.access" using ($1):($2) lw 4 lc 7 ps 2 title 'Unlock Store'
