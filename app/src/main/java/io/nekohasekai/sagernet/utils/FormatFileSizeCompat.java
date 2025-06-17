package io.nekohasekai.sagernet.utils;

import android.content.Context;
import android.os.Build;
import android.text.format.Formatter;
import static io.nekohasekai.sagernet.utils.FormatFileSize.FLAG_IEC_UNITS;
import static io.nekohasekai.sagernet.utils.FormatFileSize.FLAG_SHORTER;

public class FormatFileSizeCompat {

    public static String formatFileSize(Context context, long sizeBytes) {
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.N_MR1) {
            // In Build.VERSION_CODES.N_MR1 and earlier, android.text.format.Formatter.formatFileSize uses powers of 1024,
            // with KB = 1024 bytes, MB = 1,048,576 bytes, etc.
            return FormatFileSize.formatFileSize(context, sizeBytes);
        }
        return Formatter.formatFileSize(context, sizeBytes);
    }

    public static String formatShortFileSize(Context context, long sizeBytes) {
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.N_MR1) {
            // In Build.VERSION_CODES.N_MR1 and earlier, android.text.format.Formatter.formatFileSize uses powers of 1024,
            // with KB = 1024 bytes, MB = 1,048,576 bytes, etc.
            return FormatFileSize.formatShortFileSize(context, sizeBytes);
        }
        return Formatter.formatShortFileSize(context, sizeBytes);
    }

    public static String formatFileSize(Context context, long sizeBytes, boolean useIEC) {
        if (useIEC) {
            return FormatFileSize.formatFileSize(context, sizeBytes, FLAG_IEC_UNITS);
        }
        return formatFileSize(context, sizeBytes);
    }

    public static String formatShortFileSize(Context context, long sizeBytes, boolean useIEC) {
        if (useIEC) {
            return FormatFileSize.formatFileSize(context, sizeBytes, FLAG_IEC_UNITS | FLAG_SHORTER);
        }
        return formatShortFileSize(context, sizeBytes);
    }

}
