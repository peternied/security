/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.action.configupdate;

import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.nodes.BaseNodesRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.securityconf.impl.CType;

public class ConfigUpdateRequest extends BaseNodesRequest<ConfigUpdateRequest> {

    private CType[] configTypes;
    private Long[] sequenceIds;

    public ConfigUpdateRequest(StreamInput in) throws IOException {
        super(in);
        this.configTypes = CType.fromStringValues(in.readStringArray());
        // For backwards compability during mixed cluster scenarios need to cleanly deserialize
        if (in.available() != 0) {
            this.sequenceIds = ConfigUpdateRequest.longArrayFromStringValues(in.readStringArray());
        }
    }

    public ConfigUpdateRequest() {
        super(new String[0]);
    }

    /**
     * @param configTypes The types of configuration that should be reloaded
     * @param sequenceIds Sequence numbers that should be smaller than the values from reloaded configuration, if null ignored.
     */
    public ConfigUpdateRequest(final CType[] configTypes, final Long[] sequenceIds) {
        this();
        this.configTypes = configTypes;
        this.sequenceIds = sequenceIds;
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeStringArray(prepToSerialize(configTypes));
        out.writeStringArray(prepToSerialize(sequenceIds));
    }

    public Map<CType, Long> getTypeAndSequenceIdMap() {
        return IntStream.range(0, configTypes.length)
            .boxed()
            .collect(Collectors.toMap(i -> configTypes[i], i -> sequenceIds != null ? sequenceIds[i] : null));
    }

    @Override
    public ActionRequestValidationException validate() {
        if (configTypes == null || configTypes.length == 0) {
            return new ActionRequestValidationException();
        }
        return null;
    }

    // TODO BEFORE-MERGE: Need to be sure unit test capture these scenarios

    private static String[] prepToSerialize(final CType[] ctypes) {
        if (ctypes == null) {
            return null;
        }

        final String[] serializedReady = new String[ctypes.length];
        for (int i = 0; i < ctypes.length; i++) {
            serializedReady[i] = ctypes[i] + "";
        }
        return serializedReady;
    }

    private static String[] prepToSerialize(final Long[] longs) {
        if (longs == null) {
            return null;
        }

        final String[] serializedReady = new String[longs.length];
        for (int i = 0; i < longs.length; i++) {
            serializedReady[i] = longs[i] != null ? longs[i] + "" : null;
        }
        return serializedReady;
    }

    private static Long[] longArrayFromStringValues(final String[] longsAsStrings) {
        if (longsAsStrings == null) {
            return null;
        }

        final Long[] asLongs = new Long[longsAsStrings.length];
        for (int i = 0; i < longsAsStrings.length; i++) {
            asLongs[i] = longsAsStrings[i] != null ? Long.parseLong(longsAsStrings[i]) : null;
        }
        return asLongs;
    }
}
