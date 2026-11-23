package dev.smbserver.smb;

import java.io.File;

public final class Share {
    public final String name;
    public final File root;
    public final String remark;
    public final boolean ipc;

    public Share(String name, File root, String remark) {
        this(name, root, remark, false);
    }

    Share(String name, File root, String remark, boolean ipc) {
        this.name = name;
        this.root = root;
        this.remark = remark;
        this.ipc = ipc;
    }
}
