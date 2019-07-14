package Server;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.HashMap;

public interface IRMISniff extends Remote {

    /**
     *
     * @author Glowa
     * @return 
     * @throws java.rmi.RemoteException
     */
    public String connect() throws RemoteException;
    public int startSniff() throws RemoteException;
    public int stopSniff() throws RemoteException;
    public long dajWej() throws RemoteException;
    public long dajWyj() throws RemoteException;
    public long dajProm() throws RemoteException;
    public long dajTotal() throws RemoteException;
    public long dajMB() throws RemoteException;
    public HashMap dajIPwej() throws RemoteException;
    public HashMap dajIPwyj() throws RemoteException;
    public HashMap dajIloscwej() throws RemoteException;
    public HashMap dajIloscwyj() throws RemoteException;
}
