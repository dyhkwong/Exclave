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

package io.nekohasekai.sagernet.database;

import androidx.annotation.NonNull;

import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import io.nekohasekai.sagernet.SubscriptionType;
import io.nekohasekai.sagernet.fmt.Serializable;
import io.nekohasekai.sagernet.ktx.KryosKt;

public class SubscriptionBean extends Serializable {

    public Integer type;
    public String link;
    public String token;
    public Boolean deduplication;
    public Boolean updateWhenConnectedOnly;
    public String customUserAgent;
    public Boolean autoUpdate;
    public Integer autoUpdateDelay;
    public Long lastUpdated;
    public Long bytesUsed;
    public Long bytesRemaining;
    public Long expiryDate;

    public String nameFilter;

    // Open Online Config
    public String username;
    public List<String> protocols;

    public Set<String> selectedGroups;
    public Set<String> selectedOwners;
    public Set<String> selectedTags;

    public SubscriptionBean() {
    }

    @Override
    public void serializeToBuffer(ByteBufferOutput output) {
        output.writeInt(6);

        output.writeInt(type);

        if (type == SubscriptionType.OOCv1) {
            output.writeString(token);
        } else {
            output.writeString(link);
        }

        output.writeBoolean(deduplication);
        output.writeBoolean(updateWhenConnectedOnly);
        output.writeString(customUserAgent);
        output.writeBoolean(autoUpdate);
        output.writeInt(autoUpdateDelay);
        output.writeLong(lastUpdated);
        output.writeLong(bytesUsed);
        output.writeLong(bytesRemaining);
        output.writeLong(expiryDate);
        output.writeString(nameFilter);

        if (type == SubscriptionType.OOCv1) {
            output.writeString(username);
            KryosKt.writeStringList(output, protocols);
            KryosKt.writeStringList(output, selectedGroups);
            KryosKt.writeStringList(output, selectedOwners);
            KryosKt.writeStringList(output, selectedTags);
        }

    }

    public void serializeForShare(ByteBufferOutput output) {
        output.writeInt(5);

        output.writeInt(type);

        if (type == SubscriptionType.OOCv1) {
            output.writeString(token);
        } else {
            output.writeString(link);
        }

        output.writeBoolean(deduplication);
        output.writeBoolean(updateWhenConnectedOnly);
        output.writeString(customUserAgent);
        output.writeLong(bytesUsed);
        output.writeLong(bytesRemaining);
        output.writeLong(expiryDate);
        output.writeString(nameFilter);

        if (type == SubscriptionType.OOCv1) {
            output.writeString(username);
            KryosKt.writeStringList(output, protocols);
        }

    }

    @Override
    public void deserializeFromBuffer(ByteBufferInput input) {
        int version = input.readInt();

        type = input.readInt();
        if (type == SubscriptionType.OOCv1) {
            token = input.readString();
        } else {
            link = input.readString();
        }
        if (version < 6) {
            input.readBoolean(); // forceResolve, removed
        }
        deduplication = input.readBoolean();
        if (version < 2) input.readBoolean();
        updateWhenConnectedOnly = input.readBoolean();
        customUserAgent = input.readString();
        autoUpdate = input.readBoolean();
        autoUpdateDelay = input.readInt();
        if (version <= 3) {
            lastUpdated = (long) input.readInt();
        } else {
            lastUpdated = input.readLong();
        }


        if (type == SubscriptionType.RAW && version == 3) {
            input.readString(); // subscriptionUserinfo, removed
        }

        if (type != SubscriptionType.RAW || version >= 4) {
            bytesUsed = input.readLong();
            bytesRemaining = input.readLong();
        }

        if (version >= 4) {
            expiryDate = input.readLong();
        }

        if (version >= 5) {
            nameFilter = input.readString();
        }

        if (type == SubscriptionType.OOCv1) {
            username = input.readString();
            if (version <= 3) {
                expiryDate = (long) input.readInt();
            }
            protocols = KryosKt.readStringList(input);
            if (input.canReadVarInt()) {
                selectedGroups = KryosKt.readStringSet(input);
                if (version >= 1) {
                    selectedOwners = KryosKt.readStringSet(input);
                }
                selectedTags = KryosKt.readStringSet(input);
            }
        }
    }

    public void deserializeFromShare(ByteBufferInput input) {
        int version = input.readInt();

        type = input.readInt();
        if (type == SubscriptionType.OOCv1) {
            token = input.readString();
        } else {
            link = input.readString();
        }
        if (version < 5) {
            input.readBoolean(); // forceResolve, removed
        }
        deduplication = input.readBoolean();
        if (version < 1) input.readBoolean();
        updateWhenConnectedOnly = input.readBoolean();
        customUserAgent = input.readString();

        if (type == SubscriptionType.RAW && version == 2) {
            input.readString(); // subscriptionUserinfo, removed
        }

        if (type != SubscriptionType.RAW || version >= 3) {
            bytesUsed = input.readLong();
            bytesRemaining = input.readLong();
        }

        if (version >= 3) {
            expiryDate = input.readLong();
        }

        if (version >= 4) {
            nameFilter = input.readString();
        }

        if (type == SubscriptionType.OOCv1) {
            username = input.readString();
            if (version <= 2) {
                expiryDate = (long) input.readInt();
            }
            protocols = KryosKt.readStringList(input);
        }
    }

    @Override
    public void initializeDefaultValues() {
        if (type == null) type = SubscriptionType.RAW;
        if (link == null) link = "";
        if (token == null) token = "";
        if (deduplication == null) deduplication = false;
        if (updateWhenConnectedOnly == null) updateWhenConnectedOnly = false;
        if (customUserAgent == null) customUserAgent = "";
        if (autoUpdate == null) autoUpdate = false;
        if (autoUpdateDelay == null) autoUpdateDelay = 280;
        if (lastUpdated == null) lastUpdated = 0L;

        if (bytesUsed == null) bytesUsed = 0L;
        if (bytesRemaining == null) bytesRemaining = 0L;
        if (nameFilter == null) nameFilter = "";

        if (username == null) username = "";
        if (expiryDate == null) expiryDate = 0L;
        if (protocols == null) protocols = new ArrayList<>();
        if (selectedGroups == null) selectedGroups = new LinkedHashSet<>();
        if (selectedOwners == null) selectedOwners = new LinkedHashSet<>();
        if (selectedTags == null) selectedTags = new LinkedHashSet<>();

    }

    public static final Creator<SubscriptionBean> CREATOR = new CREATOR<SubscriptionBean>() {
        @NonNull
        @Override
        public SubscriptionBean newInstance() {
            return new SubscriptionBean();
        }

        @Override
        public SubscriptionBean[] newArray(int size) {
            return new SubscriptionBean[size];
        }
    };

}
