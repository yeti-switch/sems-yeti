set height 0
set print null-stop on

set $s = &DILog::ring_buf[0]
set $e = &DILog::ring_buf[DILog::pos]
#set $n = DILog::pos
#set $e = &DILog::ring_buf[$n]
#set $i = 0

#while $i < $n
#        #x/s DILog::ring_buf[$i]
#        printf "%s", DILog::ring_buf[$i]
#        set $i = $i+1
#end

dump binary memory di_log.dump.bin $s $e 

quit
