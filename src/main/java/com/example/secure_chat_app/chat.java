package com.example.secure_chat_app;

import java.io.Serial;
import java.io.Serializable;

public class chat implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;
    byte[] data;

    chat(byte[] data){
        this.data = data;
    }


    byte[] getData(){
        return data;
    }

}
