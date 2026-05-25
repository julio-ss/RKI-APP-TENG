package br.zire.rkiapp.util;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.widget.Toast;

import br.zire.rkiapp.R;

public class Dialogs {
    //Progress bar variable.
    static ProgressDialog progressDialog;

    public static void dialogShow(Context context, String title, String message){
        AlertDialog.Builder dialog = new AlertDialog.Builder(context);
        dialog.setTitle(title);
        dialog.setMessage(message);
        dialog.setPositiveButton("Ok", null);
        dialog.show();
    }
}
