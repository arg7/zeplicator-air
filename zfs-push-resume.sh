#!/bin/bash

        echo Put some data on master fs
	cnt=20
	sz=256
	for i in {1..${cnt}}; do 
		sudo dd if=/dev/urandom of="/var/lib/zep-air/mnt/za-master-pool/master/file_$i.bin" bs=1k count=${sz} status=none
	done

	tm=$(date +%Y%m%d-%H%M%S)

        snap="za-master-pool/master@${tm}"
	zfs snapshot "${snap}"
	echo Created snapshot ${snap}

	#get total stream size
	sz=$(zfs send ${snap} | wc -c)
	cut=$(( $sz / 10 ))

	#can't be lower zfs record_size
	[ ${cut} -lt 150000 ] && cut=150000

	echo "$cnt files has been created with total size of $(numfmt --to=si ${sz})"

        # === On serve host ===

        cnt=0
        send_opt="${snap}"
	# create backup folder
	mkdir -p "/tmp/${snap}"
	fsn="/tmp/${snap}/stream"

	#set small chunk size, to test garbage in scenario on first run
	sz=10
	fs=""

        # For test we insert head -c ${sz} after zfs send to simulate interrupted transfer.
        while true
        do
                chunk="/tmp/${snap}/$(printf '%04d' $cnt).zfs"

		echo
		echo "*>>>"
		echo "receiving upto $(numfmt --to=si ${sz}) bytes in to ${chunk}"

		# reaching to master host to fetch snaphot stream with resume feature
		# we should use WS pipe to send  cmd and receive stdout and stderr
                ssh za-master "set -o pipefail; zfs send ${send_opt}  | head -c ${sz}" 2>/tmp/zfs_send_err > ${chunk}
		zfs_rc=$?

		#next time use random chunk size
		sz=$(( 8 + (RANDOM % 5) * ${cut} ))

		#test if new chunk is legit
		zstream token -g -i ${chunk} 2>/tmp/zfs_token_err > /dev/null
		[ $? -eq 1 ] && echo "retry, garbage recieved, cause: $(cat /tmp/zfs_token_err)" && continue

		echo "join new chunk"
		zstream join ${fs} ${chunk} > ${fsn}.tmp 2>/tmp/zfs_join_err
		rc=$?
                mv -f ${fsn}.tmp ${fsn}
		[ $rc -eq 0 ] && echo "last chunk received, zfs pipe exit code ${zfs_rc}" && break

		echo -n "resume token generation: "
                token=$(zstream token -g -i ${fsn})
		#check if got token, if not - we received garbage and should try again...
		[ -z "${token}" ] && echo "panic, damaged stream: ${fsn}" && exit 1
		echo "ok"

		fs=${fsn}
		send_opt="-t ${token}"
		cnt=$((cnt+1))

        done

	echo
	echo "*<<<"
        # zfs recv signaled success, last chunk was received
	echo "received $cnt chunks:"
	ls -lha /tmp/${snap}/*.zfs
	#echo "cleaning"
        #rm /tmp/${snap}/*.zfs
	echo "full stream assembled:"
	ls -lha ${fsn}
