package net.floodlightcontroller.DDoS;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import net.floodlightcontroller.DDoS.Server.Host;

public class Server {
	private Map<String, Host> hosts;
	private String IP;
	public Server(String ip){
		IP = ip;
		hosts = new HashMap<String,Host>();
	}
	public void addHost(String ip, String indicator ){
		if(this.IP.equals(ip)){
			return;
		}
		Host host = hosts.get(ip);
		if(host==null){
			host =new Host(ip);
			hosts.put(ip, host);
			addValue(indicator,host);
		}else{
			addValue(indicator,host);
		}
	}
	public void addValue(String indicator,Host host){
		switch(indicator){
		case "SYN":
			host.addSYN();
			break;
		case "SYNACK":
			host.addSYNACK();
			break;
		case "FIN":
			host.addFIN();
			break;
		case "FINACK":
			host.addFINACK();
			break;
		case "ACK":
			host.addACK();
			break;
		}
	}
	public String getIP(){
		return this.IP;
	}
	
	public void removeHost(Host host){
		hosts.remove(host.IPaddress);
	}
	public ArrayList<Host> gethost(){
		ArrayList<Host> attachedHost=new ArrayList<Host>();
		Iterator<Host> iterator = hosts.values().iterator();
		while(iterator.hasNext()){
			attachedHost.add(iterator.next());
		}
		return attachedHost;
	}
	
	public int getSYN(Host h){
		return h.SYNflags;
	}
	
	public int getSYNACK(Host h){
		return h.SYNACKflags;
	}
	public int getACK(Host h){
		return h.ACKflags;
	}
	public int getFIN(Host h){
		return h.FINflags;
	}
	
	public int countHost(){
		return hosts.size();
	}
	
	public class Host{
		private int SYNflags;
		private int SYNACKflags;
		private int FINflags;
		private int ACKflags;
		private int FINACKflags;
		private String IPaddress;
		
		public Host(String ip){
			IPaddress = ip;
			SYNACKflags=0;
			SYNflags=0;
			FINflags=0;
			ACKflags=0;
			FINACKflags=0;
		}
		public void addSYN(){
			this.SYNflags++;
		}
		public void addACK(){
			this.ACKflags++;
		}
		public void addSYNACK(){
			this.SYNACKflags++;
		}
		
		public void addFIN(){
			this.FINflags++;
		}
		
		public void addFINACK(){
			this.FINACKflags++;
		}
		public void clean(){
			SYNACKflags=0;
			SYNflags=0;
			FINflags=0;
			FINACKflags=0;
			ACKflags=0;
		}
		public String getIP(){
			return this.IPaddress;
		}
	}
}
