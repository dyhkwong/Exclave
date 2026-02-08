/******************************************************************************
 *                                                                            *
 * Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>             *
 *                                                                            *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU General Public License as published by       *
 * the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                       *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.fmt.v2ray;

import androidx.annotation.NonNull;

import org.jetbrains.annotations.NotNull;

import io.nekohasekai.sagernet.fmt.AbstractBean;
import io.nekohasekai.sagernet.fmt.KryoConverters;

public class VMessBean extends StandardV2RayBean {

    public Integer alterId;

    public Boolean experimentalAuthenticatedLength;
    public Boolean experimentalNoTerminationSignal;

    @Override
    public void initializeDefaultValues() {
        if (alterId == null) alterId = 0;
        if (experimentalAuthenticatedLength == null) experimentalAuthenticatedLength = false;
        if (experimentalNoTerminationSignal == null) experimentalNoTerminationSignal = false;

        if (encryption == null) encryption = "auto";
        super.initializeDefaultValues();
    }

    @Override
    public void applyFeatureSettings(AbstractBean other) {
        super.applyFeatureSettings(other);
        if (!(other instanceof VMessBean bean)) return;
        bean.experimentalAuthenticatedLength = experimentalAuthenticatedLength;
        bean.experimentalNoTerminationSignal = experimentalNoTerminationSignal;
    }

    @NotNull
    @Override
    public VMessBean clone() {
        return KryoConverters.deserialize(new VMessBean(), KryoConverters.serialize(this));
    }

    public static final Creator<VMessBean> CREATOR = new CREATOR<>() {
        @NonNull
        @Override
        public VMessBean newInstance() {
            return new VMessBean();
        }

        @Override
        public VMessBean[] newArray(int size) {
            return new VMessBean[size];
        }
    };

    @Override
    public boolean isInsecure() {
        switch (encryption) {
            case "auto", "aes-128-gcm", "chacha20-poly1305":
                return false;
        }
        return super.isInsecure();
    }

}
