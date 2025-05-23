package org.satocash.applet;

import javacard.framework.Util;
import javacard.framework.ISOException;

/**
 * Object Manager Class
 * <p>
 * 
 * Objects are linked in a list in the dynamic memory. No smart search is done
 * at the moment.
 * 
 * Notation: 
 *  Base address: starting address of the object's header
 *  Data address: starting address of the object's data
 *  Data_address= Base_adresss + OBJ_HEADER_SIZE
 * 
 * <p>
 * 
 * Object fields:
 * 
 * <pre>
 *   short next (2 byte)
 *   short obj_class (2 bytes) // TODO: remove - unused?
 *   short obj_id (2 bytes)
 *   short obj_size (2 bytes)
 *   byte[] data
 * </pre>
 * 
 * TODO - Could we definitively avoid a map enforcing the ID (equal to the
 * memory address, i.e.) - security implications ?
 * 
 */

public class ObjectManager {

    private final static byte OBJ_HEADER_SIZE = (byte) (6 + 2);
    private final static byte OBJ_H_NEXT = (byte) 0; // Short size;
    private final static byte OBJ_H_CLASS = (byte) 2; // Short ocj_class; // todo: unused?
    public  final static byte OBJ_H_ID = (byte) 4; // Short obj_id;
    private final static byte OBJ_H_SIZE = (byte) 6;//12; // Short size;

    /** There have been memory problems on the card */
    public final static short SW_NO_MEMORY_LEFT = (short) 0x9C01;
    public final static short SW_OBJECT_NOT_FOUND= (short) 0x9C08;

    /**
     * Iterator on objects. Stores the offset of the last retrieved object's
     * record.
     */
    private short it;

    /** The Memory Manager object */
    private MemoryManager mem = null;

    /** Map for fast search of objects (unimplemented) */
    // static Map map;

    /** Head of the objects' list */
    private short obj_list_head = MemoryManager.NULL_OFFSET;

    /** Number of secret stored */
    private short nb_objects = (short)0;

    /**
     * Constructor for the ObjectManager class.
     * 
     * @param mem_ref
     *            The MemoryManager object to be used to allocate objects'
     *            memory.
     */
    public ObjectManager(short mem_size) {//(MemoryManager mem_ref) {
        mem= new MemoryManager(mem_size);
        obj_list_head = MemoryManager.NULL_OFFSET;
    }
    
    /**
     * Creates an object with specified parameters. Throws a SW_NO_MEMORY_LEFT
     * exception if cannot allocate the memory. Does not check if object exists.
     * 
     * 
     * @return The memory base address for the object. It can be used in
     *         successive calls to xxxFromAddress() methods.
     */
    public boolean resetObjectManager(boolean secure_erase) {
        mem.resetMemory(secure_erase);
        obj_list_head = MemoryManager.NULL_OFFSET;
        nb_objects= (short)0;
        return true;
    }

    /**
     * Get available free memory
     * 
     * @return The total amount of available free memory
     */
    public short freemem() {
        return mem.freemem();
    }

    /**
     * Get total memory
     * 
     * @return The total amount of memory
     */
    public short totalmem() {
        return mem.totalmem();
    }

    /**
     * Get number of object in memory
     * 
     * @return The number of object in memory
     */
    public short getObjectNumber() {
        return nb_objects;
    }

    /**
     * Creates an object with specified parameters. Throws a SW_NO_MEMORY_LEFT
     * exception if cannot allocate the memory. Does not check if object exists.
     * 
     * @param type
     *            Object Type
     * @param id
     *            Object ID (Type and ID form a generic 4 bytes identifier)
     * @return The memory base address for the object. It can be used in
     *         successive calls to xxxFromAddress() methods.
     */
    public short createObject(short type, short id, short size, boolean secure) {
        /* Allocate memory for new object */
        short base = mem.alloc((short) (size + OBJ_HEADER_SIZE));
        if (base == MemoryManager.NULL_OFFSET)
            ISOException.throwIt(SW_NO_MEMORY_LEFT);
        /* New obj will be inserted in the head of the list */
        mem.setShort(base, OBJ_H_NEXT, obj_list_head);
        mem.setShort(base, OBJ_H_CLASS, type);
        mem.setShort(base, OBJ_H_ID, id);
        mem.setShort(base, OBJ_H_SIZE, size);
        //mem.setBytes(base, OBJ_H_ACL, acl_buf, acl_offset, OBJ_ACL_SIZE);
        obj_list_head = base;

        // reset object memory 
        if (secure){
            Util.arrayFillNonAtomic(mem.getBuffer(), (short) (base + OBJ_HEADER_SIZE), mem.getShort(base, OBJ_H_SIZE), (byte) 0x00);
        }
        
        /* Add to the map */
        // map.addEntry(type, id, base);
        nb_objects++;

        // Return data-address
        return (short) (base + OBJ_HEADER_SIZE);
    }

    /** Creates an object with the maximum available size */
    public short createObjectMax(short type, short id) {
        short obj_size = mem.getMaxSize();
        if (obj_size == (short) 0)
            ISOException.throwIt(SW_NO_MEMORY_LEFT);
        /*
         * The object's real size must take into account that extra bytes are
         * needed for the header
         */
        return createObject(type, id, (short) (obj_size - OBJ_HEADER_SIZE), false);
    }

    /**
     * Clamps an object freeing the unused memory
     * 
     * @param type
     *            Object Type
     * @param id
     *            Object ID (Type and ID form a generic 4 bytes identifier)
     * @param new_size
     *            The new object size (must be less than current size)
     * @return True if clamp was possible, false otherwise
     */
    public boolean clampObject(short type, short id, short new_size) {
        short base = getEntry(type, id);
        if (base == MemoryManager.NULL_OFFSET)
            ISOException.throwIt(SW_OBJECT_NOT_FOUND);
        // Delegate every check to the Memory Manager
        if (mem.realloc(base, (short) (new_size + OBJ_HEADER_SIZE))) {
            mem.setShort(base, OBJ_H_SIZE, new_size);
            return true;
        }
        return false;
    }

    /**
     * Clamps an object freeing the unused memory. 
     * This method is faster than clampObject(short type, short id, short new_size) 
     * since base address is already provided and do not need to be searched.
     * 
     * @param base
     *            The base address as returned by getBaseAddress().
     *            This is located after the object metadata header (OBJ_HEADER_SIZE)
     * @param new_size
     *            The new object size (must be less than current size)
     * @return True if clamp was possible, false otherwise
     */
    public boolean clampObject(short base, short new_size) {
        if (base == MemoryManager.NULL_OFFSET)
            ISOException.throwIt(SW_OBJECT_NOT_FOUND);
        // compute base pointer (start of oject header) from base address (start of object data)
        base-= OBJ_HEADER_SIZE;
        // Delegate every check to the Memory Manager
        if (mem.realloc(base, (short) (new_size + OBJ_HEADER_SIZE))) {
            mem.setShort(base, OBJ_H_SIZE, new_size);
            return true;
        }
        return false;
    }

    /** Write data at the specified location in an object */
    public void setObjectData(short base, short base_offset, byte[] src_data, short src_offset, short len) {
        // TODO: short dst_base = map.getEntry(type, id);
        mem.setBytes(base, base_offset, src_data, src_offset, len);
    }
    public void setObjectByte(short base, short base_offset, byte val) {
        mem.setByte(base, base_offset, val);
    }

    /** Read data from the specified location in an object */
    public void getObjectData(short base, short base_offset, byte[] dst_data, short dst_offset, short len) {
        // TODO: short dst_base = map.getEntry(type, id);
        mem.getBytes(dst_data, dst_offset, base, base_offset, len);
    }
    public byte getObjectByte(short base, short base_offset) {
        return mem.getByte(base, base_offset);
    }
    
    /**
     * Destroy the specified object
     * 
     * @param type
     *            Object Type
     * @param id
     *            Object ID (Type and ID form a generic 4 bytes identifier)
     * @param secure
     *            If true, object memory is zeroed before being released.
     * @return true if object was destroyed, false otherwise
     */
    public boolean destroyObject(short type, short id, boolean secure) {
        short base = obj_list_head;
        short prev = MemoryManager.NULL_OFFSET;
        boolean found = false;
        while ((!found) && (base != MemoryManager.NULL_OFFSET)) {
            if ((mem.getShort(base, OBJ_H_CLASS) == type) && (mem.getShort(base, OBJ_H_ID) == id))
                found = true;
            else {
                prev = base;
                base = mem.getShort(base, OBJ_H_NEXT);
            }
        }
        if (found) {
            // Unlink object from the list
            if (prev != MemoryManager.NULL_OFFSET) {
                mem.setShort(prev, OBJ_H_NEXT, mem.getShort(base, OBJ_H_NEXT));
            } else {
                obj_list_head = mem.getShort(base, OBJ_H_NEXT);
            }
            // Zero memory if required
            if (secure){
                Util.arrayFillNonAtomic(mem.getBuffer(), (short) (base + OBJ_HEADER_SIZE), mem.getShort(base,OBJ_H_SIZE), (byte) 0x00);
            }

            // Free memory
            mem.free(base);
            nb_objects--;
            return true;
        } 
            
        return false;
    }

    /**
     * Returns the header base address (offset) for the specified object
     * <p>
     * Object header is found at the returned offset, while object data starts
     * right after the header
     * <p>
     * This performs a linear search, so performance issues could arise as the
     * number of objects grows If object is not found, then returns NULL_OFFSET
     * 
     * @param type
     *            Object Type
     * @param id
     *            Object ID (Type and ID form a generic 4 bytes identifier)
     * @return The starting offset of the object or NULL_OFFSET if the object is
     *         not found.
     */
    private short getEntry(short type, short id) {
        /*
         * This is a stupid linear search. It's fine for a few objects. TODO:
         * Use a map for high number of objects
         */
        short base = obj_list_head;
        while (base != MemoryManager.NULL_OFFSET) {
            if ((mem.getShort(base, OBJ_H_CLASS) == type) && (mem.getShort(base, OBJ_H_ID) == id))
                return base;
            base = mem.getShort(base, OBJ_H_NEXT);
        }
        return MemoryManager.NULL_OFFSET;
    }
    
    /* PUBLIC METHODS */

    /**
     * Returns the data address (offset) for an object.
     * <p>
     * The address can be used for further calls to xxxFromAddress()
     * methods
     * <p>
     * This function should only be used if performance issue arise.
     * setObjectData() and getObjectData() should be used, instead.
     * 
     * @param type
     *            Object Type
     * @param id
     *            Object ID (Type and ID form a generic 4 bytes identifier)
     * @return The starting offset of the object. At this location
     */
    public short getBaseAddress(short type, short id) {
        short base = getEntry(type, id);
        if (base == MemoryManager.NULL_OFFSET)
            return MemoryManager.NULL_OFFSET;
        else
            return ((short) (base + OBJ_HEADER_SIZE));
    }

    /**
     * Checks if an object exists
     * 
     * @param type
     *            The object type
     * @param id
     *            The object ID
     * @return true if object exists
     */
    public boolean exists(short type, short id) {
        short base = getEntry(type, id);
        return (base != MemoryManager.NULL_OFFSET);
    }

    /** Returns object size from the base address */
    public short getSizeFromAddress(short base) {
        return mem.getShort((short) (base -OBJ_HEADER_SIZE + OBJ_H_SIZE));
    }
    /** Returns object id from the base address */
    public short getIdFromAddress(short base) {
        return mem.getShort((short) (base -OBJ_HEADER_SIZE + OBJ_H_ID));
    }
    
    /**
     * Resets the objects iterator and retrieves the information record of the
     * first object, if any.
     * <p>
     * 
     * @return The base address of the first object, or NULL_OFFSET if none.
     * 
     * @see #getNextRecord
     */
    public short getFirstRecord() {
        it = obj_list_head;
        return getNextRecord();
    }
    
    /**
     * Retrieves the information record of the next object, if any.
     * <p>
     * 
     * @return 
     *          The base address of the object or NULL_OFFSET if there is no more object.
     * @see #getFirstRecord
     */
    public short getNextRecord() {
        if (it == MemoryManager.NULL_OFFSET)
            return MemoryManager.NULL_OFFSET;
        short base= (short)(it+OBJ_HEADER_SIZE);
        // Advance iterator
        it = mem.getShort(it, OBJ_H_NEXT);
        return base;
    }

} // class MemoryManager