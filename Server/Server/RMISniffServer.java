package Server;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.RMISecurityManager;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RMISniffServer {

    public static void main(String[] args) {
        try {
            int registryPort = 7000;
//            if (System.getSecurityManager() == null) {
//                System.setSecurityManager(new RMISecurityManager());
//            }
            
            RMISniff server = new RMISniff();
            LocateRegistry.createRegistry(registryPort);
            UnicastRemoteObject.exportObject(server);
            Naming.rebind("//localhost:" + registryPort + "/SniffServer", server);
            System.out.println("Serwer sniffera dziala, mozna pracowac ... ");
            server.connect();
            server.startSniff();
            
        } catch (MalformedURLException | RemoteException ex) {
            Logger.getLogger(RMISniffServer.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}

