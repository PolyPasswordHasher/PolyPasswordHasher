guessespersecond = 1.0*10**9
charsperpassword = 95.0
partialbits = 16.0

for passwordlength in range(6,13):
   bestpracticetime = charsperpassword ** passwordlength / guessespersecond
   t2time = charsperpassword ** (passwordlength * 2) / guessespersecond
   t3time = charsperpassword ** (passwordlength * 3) / guessespersecond
   t2timep = (bestpracticetime*2 + (charsperpassword ** passwordlength * 1.0 / 2** partialbits)**2) / guessespersecond
   t3timep = (bestpracticetime*3 + (charsperpassword ** passwordlength * 1.0 / 2** partialbits)**3) / guessespersecond

   print passwordlength, bestpracticetime, t2time, t3time, t2timep, t3timep
