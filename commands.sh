./xray -n us-west-2 --log-level dev --log-file ../xraylog.log &


-javaagent:/<path-to-disco>/disco-java-agent.jar=pluginPath=/<path-to-disco>/disco-plugins


java -ea -Djava.library.path=/opt/cloudhsm/lib/ -jar target/assembly/login-runner.jar --method explicit --user nsnaws --password Firepolo2! --partition 13.0.0.250




sudo tcpdump -n dst 13.0.0.250 -W 1 -C 200 -w ~/git/tcpdumplogs/file.pcap &
cd ~/git/aws-cloudhsm-jce-examples
java -ea -Djava.library.path=/opt/cloudhsm/lib/ -jar target/assembly/login-runner.jar --method enviroment
cat ~/git/tcpdumplogs/file.pcap



export LD_LIBRARY_PATH=/opt/cloudhsm/lib
export HSM_PARTITION=13.0.0.250
export HSM_USER=nsnaws
export HSM_PASSWORD=Firepolo2!

java -ea -Djava.library.path=/opt/cloudhsm/lib/ -jar target/assembly/login-runner.jar --method enviroment

