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

package io.nekohasekai.sagernet.aidl;

import io.nekohasekai.sagernet.aidl.TrafficStats;
import io.nekohasekai.sagernet.aidl.AppStatsList;

oneway interface ISagerNetServiceCallback {
  void stateChanged(int state, String profileName, String msg);
  void trafficUpdated(long profileId, in TrafficStats stats, boolean isCurrent);
  void statsUpdated(in AppStatsList statsList);
  void observatoryResultsUpdated(long groupId);
  // Traffic data has persisted to database, listener should refetch their data from database
  void profilePersisted(long profileId);
  void missingPlugin(String profileName, String pluginName);
  void routeAlert(int type, String routeName);
}
