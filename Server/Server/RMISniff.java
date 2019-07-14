package Server;

import java.io.IOException;
import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RMISniff implements IRMISniff {
    Sniff sniffer;
    
    @Override
    public String connect() throws RemoteException {
        return "Sniffer dziala...";
    }
    
    @Override
    public int startSniff() throws RemoteException {
        sniffer = new Sniff();
        try {
            if (sniffer.start() != 0)
                return -1;
        } catch (IOException ex) {
            Logger.getLogger(RMISniff.class.getName()).log(Level.SEVERE, null, ex);
        }
        return 0;
    }

    @Override
    public int stopSniff() throws RemoteException {
        sniffer.stop();
        return 0;
    }

    @Override
    public long dajWej() throws RemoteException {
        return sniffer.dajWej();
    }

    @Override
    public long dajWyj() throws RemoteException {
        return sniffer.dajWyj();
    }

    @Override
    public long dajProm() throws RemoteException {
        return sniffer.dajProm();
    }    
    
    @Override
    public long dajTotal() throws RemoteException {
        return sniffer.dajTotal();
    }
    
    @Override
    public long dajMB() throws RemoteException {
        return sniffer.dajMB();
    }    
    
    @Override
    public HashMap dajIPwej() throws RemoteException {
        return sniffer.dajIPwej();
    } 

    @Override
    public HashMap dajIPwyj() throws RemoteException {
        return sniffer.dajIPwej();
    }
    
    @Override
    public HashMap dajIloscwej() throws RemoteException {
        return sniffer.dajIPwej();
    }
    
    @Override
    public HashMap dajIloscwyj() throws RemoteException {
        return sniffer.dajIPwej();
    }    
}

