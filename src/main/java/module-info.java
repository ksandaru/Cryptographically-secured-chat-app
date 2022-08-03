module com.example.secure_chat_app {
    requires javafx.controls;
    requires javafx.fxml;


    opens com.example.secure_chat_app to javafx.fxml;
    exports com.example.secure_chat_app;
}