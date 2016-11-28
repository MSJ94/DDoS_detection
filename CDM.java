package net.floodlightcontroller.DDoS;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.python.antlr.PythonParser.break_stmt_return;

import net.floodlightcontroller.DDoS.Server.Host;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.infoextract.ServerInfo;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.staticentry.IStaticEntryPusherService;

public class CDM implements IFloodlightModule, IOFMessageListener,Runnable {
    private IFloodlightProviderService ProviderIn;
    private IDeviceService deviceService;
    private IOFSwitchService switchService;
    private IStaticEntryPusherService flowEntryService;
    private ArrayList<Server> servers;
    private boolean hasInfo;
    private Thread thread;
    private int count=0;
    private int ack=0;
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "CDM";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {
		// TODO Auto-generated method stub
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if(eth.getEtherType()==EthType.IPv4){
			IPv4 ipv4 = (IPv4)eth.getPayload();
			String source = ipv4.getSourceAddress().toString();
			String destination = ipv4.getDestinationAddress().toString();
			boolean isServer = false;
			Server serv =null;
			for (int i = 0; i < servers.size(); i++) {
				Server s = servers.get(i);
				if(s.getIP().equals(source) || s.getIP().equals(destination)){
					isServer=true;
					serv= s;
					break;
				}
			}
			if(isServer){	
				if(ipv4.getProtocol()==IpProtocol.TCP){
					Set<DatapathId>dpids = switchService.getAllSwitchDpids();
					int size=dpids.size();
					TCP tcp = (TCP) ipv4.getPayload();
					switch (tcp.getFlags()) 
					{
					case 2: //SYN Flag
						serv.addHost(source, "SYN");
						count++;
						break;
					case 18: //SYN-ACK Flag
						serv.addHost(destination, "SYNACK");
						count++;
						break;
					case 1: //FIN Flag
						if(destination.equals(serv.getIP()))
							serv.addHost(source, "FIN");						//We only add the FIN flag if the user sends it
						break;
					case 17: //FIN-ACK Flag
						if(destination.equals(serv.getIP()))
							serv.addHost(source,"FINACK");							//We only add the FIN ACK flag if the user sends it
						break;
					case 16: //ACK
						if(count>=2){
							serv.addHost(source,"ACK");
						    ack++;
						    if(ack==size){
						    	count=0;
						    	ack=0;
						    }
						}
						break;
					default:
						break;
					}
					hasInfo = true;	
				}
				
			}
		}
		return Command.CONTINUE;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> collection = new ArrayList<Class<? extends IFloodlightService>>();
		collection.add(IFloodlightProviderService.class);
		collection.add(IStaticEntryPusherService.class);
		collection.add(IDeviceService.class);
		collection.add(IOFSwitchService.class);
		return null;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		ProviderIn = context.getServiceImpl(IFloodlightProviderService.class);
		flowEntryService = context.getServiceImpl(IStaticEntryPusherService.class);
		deviceService = context.getServiceImpl(IDeviceService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		servers = new ArrayList<Server>();
		hasInfo=false;
		try{
			File file = new File("/home/saalim/floodlight/data/servers.txt");
			BufferedReader br = new BufferedReader(new FileReader(file));
			String s;
			while((s=br.readLine())!=null){
				Server server = new Server(s);
				servers.add(server);
			}
		}catch(Exception e){
			e.printStackTrace();
		}
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		ProviderIn.addOFMessageListener(OFType.PACKET_IN, this);	
        thread = new Thread(this);
        thread.start();
	}
	int counter=0;
	@Override
	public void run(){
		int rules=0;
		while(true){
			try{
				Thread.sleep(15000);
				boolean attack=false;
				counter++;
				if(counter==8){
					if(rules>0){
						for (int i = 0; i < rules; i++) {
							String flowName = "Flow"+i;
							flowEntryService.deleteEntry(flowName);
						}
					}
					rules=0;
				}
				if(hasInfo){
					hasInfo=false;
					for (int i = 0; i < servers.size(); i++) {
						Server server = servers.get(i);
						ArrayList<Host> host = server.gethost();
						for (int j = 0; j < host.size(); j++) {
							int SYN = server.getSYN(host.get(j));
							int SYNACK = server.getSYNACK(host.get(j));
							int ACK = server.getACK(host.get(j));
							int totalFlags = SYN+SYNACK+ACK;
							double entropy=Integer.MAX_VALUE;
							if(totalFlags>0){
								double probSyn = (double)SYN/totalFlags;
								double probSynAck = (double)SYNACK/totalFlags;
								double probAck = (double)ACK/totalFlags;
								double temp1 = 0;
								double temp2 = 0;
								double temp3 = 0;
								if(probSyn != 0)
									temp1 = probSyn*(Math.log(probSyn)/Math.log(2));
								if(probSynAck != 0)
									temp2 = probSynAck*(Math.log(probSynAck)/Math.log(2));
								if(probAck != 0)	
									temp3 = probAck*(Math.log(probAck)/Math.log(2));		
								entropy = -(temp1+temp2+temp3);
								System.out.println("Entropy = "+entropy);
							}
							host.get(j).clean();
							if(entropy<1.3 && Math.abs(SYN-ACK)>5000){
								attack=true;
								Set<DatapathId>dpids = switchService.getAllSwitchDpids();
								Iterator<DatapathId> iterator = dpids.iterator();
								while(iterator.hasNext()){
									DatapathId dp = iterator.next();
									System.out.println("Switch ID: "+dp.toString());
									IOFSwitch sw = switchService.getSwitch(dp);
									OFFactory factory = sw.getOFFactory();
									System.out.println("Create flow for IP: "+host.get(j).getIP());
										Match match = factory.buildMatch()
												.setExact(MatchField.ETH_TYPE, EthType.IPv4)
												.setExact(MatchField.IPV4_DST, IPv4Address.of(server.getIP()))
												.setExact(MatchField.IPV4_SRC, IPv4Address.of(host.get(j).getIP()))
												.build();
										OFFlowAdd flowAdd = factory.buildFlowAdd()
												.setBufferId(OFBufferId.NO_BUFFER)
												.setHardTimeout(3600)
												.setIdleTimeout(10)
												.setPriority(32768)
												.setMatch(match)
												.build();
										String flowName = "Flow"+rules;
										flowEntryService.addFlow(flowName,flowAdd,dp);
										rules++;
								}
							}
							
						}
					}
					if(attack){
						counter=0;
					}
				}
			}catch(Exception e){
				e.printStackTrace();
			}
			
		}
	}

}

