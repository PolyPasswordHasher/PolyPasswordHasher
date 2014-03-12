set logscale x 2
set logscale y 10
set format x "%.0f"
set key left bottom

set xtics ("1" 1, "2" 2, "4" 4, "8" 8, "16" 16, "32" 32, "64" 64, "128" 128, "256" 256) 

set ytics ("1K" 1000, "10K" 10000, "100K" 100000)

set xrange [.8:300]
set yrange [1000:100000]
set xlabel "Threshold Value"
set ylabel "Operations per second"
set size 0.6,0.6


set object rect from 2.1,1080 to 110,3400


set terminal postscript enhanced color solid
set output "onebigperformancegraph.eps"
plot "mac.auth" using ($1):($3) title 'Authenticate Threshold', "mac.thresholdless.auth" using ($1):($3) title 'Authenticate Thresholdless', "mac.create" using ($1):($3) title 'Create Threshold Account', "mac.thresholdless.create" using ($1):($3) title 'Create Thresholdless Account'
