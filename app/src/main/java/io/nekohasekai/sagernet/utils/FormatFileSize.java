/*
 * Copyright (C) 2006 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Modified from android/text/format/Formatter.java

package io.nekohasekai.sagernet.utils;

import android.content.Context;
import android.content.res.Resources;
import android.os.Build;
import android.text.BidiFormatter;
import android.text.TextUtils;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Locale;
import io.nekohasekai.sagernet.R;

public class FormatFileSize {

    public static final int FLAG_SHORTER = 1;

    public static final int FLAG_CALCULATE_ROUNDED = 1 << 1;

    public static final int FLAG_SI_UNITS = 1 << 2;

    public static final int FLAG_IEC_UNITS = 1 << 3;

    public static class BytesResult {
        public final String value;
        public final String units;
        public final long roundedBytes;

        public BytesResult(String value, String units, long roundedBytes) {
            this.value = value;
            this.units = units;
            this.roundedBytes = roundedBytes;
        }

    }

    /** @noinspection deprecation*/
    private static Locale localeFromContext(@NonNull Context context) {
        if (Build.VERSION.SDK_INT <= 23) {
            return context.getResources().getConfiguration().locale;
        }
        return context.getResources().getConfiguration().getLocales().get(0);
    }

    private static String bidiWrap(@NonNull Context context, String source) {
        final Locale locale = localeFromContext(context);
        if (TextUtils.getLayoutDirectionFromLocale(locale) == View.LAYOUT_DIRECTION_RTL) {
            return BidiFormatter.getInstance(true /* RTL*/).unicodeWrap(source);
        } else {
            return source;
        }
    }

    public static String formatFileSize(@Nullable Context context, long sizeBytes) {
        return formatFileSize(context, sizeBytes, FLAG_SI_UNITS);
    }

    public static String formatShortFileSize(@Nullable Context context, long sizeBytes) {
        return formatFileSize(context, sizeBytes, FLAG_SI_UNITS | FLAG_SHORTER);
    }

    public static String formatFileSize(@Nullable Context context, long sizeBytes, int flags) {
        if (context == null) {
            return "";
        }
        final BytesResult result = formatBytes(context.getResources(), sizeBytes, flags);
        return bidiWrap(context, context.getString(R.string.fileSizeSuffix, result.value, result.units));
    }

    public static BytesResult formatBytes(Resources res, long sizeBytes, int flags) {
        final boolean useIEC = (flags & FLAG_IEC_UNITS) != 0;
        final int unit = useIEC ? 1024 : 1000;
        final boolean isNegative = (sizeBytes < 0);
        float result = isNegative ? -sizeBytes : sizeBytes;
        int suffix = R.string.fileSize_byte;
        long mult = 1;
        if (result > 900) {
            suffix = useIEC ? R.string.fileSize_kibibyte : R.string.fileSize_kilobyte;
            mult = unit;
            result = result / unit;
        }
        if (result > 900) {
            suffix = useIEC ? R.string.fileSize_mebibyte : R.string.fileSize_megabyte;
            mult *= unit;
            result = result / unit;
        }
        if (result > 900) {
            suffix = useIEC ? R.string.fileSize_gibibyte : R.string.fileSize_gigabyte;
            mult *= unit;
            result = result / unit;
        }
        if (result > 900) {
            suffix = useIEC ? R.string.fileSize_tebibyte : R.string.fileSize_terabyte;
            mult *= unit;
            result = result / unit;
        }
        if (result > 900) {
            suffix = useIEC ? R.string.fileSize_pebibyte : R.string.fileSize_petabyte;
            mult *= unit;
            result = result / unit;
        }
        // Note we calculate the rounded long by ourselves, but still let String.format()
        // compute the rounded value. String.format("%f", 0.1) might not return "0.1" due to
        // floating point errors.
        final int roundFactor;
        final String roundFormat;
        if (mult == 1 || result >= 100) {
            roundFactor = 1;
            roundFormat = "%.0f";
        } else if (result < 1) {
            roundFactor = 100;
            roundFormat = "%.2f";
        } else if (result < 10) {
            if ((flags & FLAG_SHORTER) != 0) {
                roundFactor = 10;
                roundFormat = "%.1f";
            } else {
                roundFactor = 100;
                roundFormat = "%.2f";
            }
        } else { // 10 <= result < 100
            if ((flags & FLAG_SHORTER) != 0) {
                roundFactor = 1;
                roundFormat = "%.0f";
            } else {
                roundFactor = 100;
                roundFormat = "%.2f";
            }
        }
        if (isNegative) {
            result = -result;
        }
        final String roundedString = String.format(roundFormat, result);
        // Note this might overflow if abs(result) >= Long.MAX_VALUE / 100, but that's like 80PB so
        // it's okay (for now)...
        final long roundedBytes =
                (flags & FLAG_CALCULATE_ROUNDED) == 0 ? 0
                        : (((long) Math.round(result * roundFactor)) * mult / roundFactor);
        final String units = res.getString(suffix);
        return new BytesResult(roundedString, units, roundedBytes);
    }
}
