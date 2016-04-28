#!/usr/bin/env python
#
# Copyright (c) 2016 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os, util
from string import Template

import callback_gen
import dto_gen

jvpp_ifc_template = Template("""
package $base_package.$callback_facade_package;

public interface CallbackJVpp extends java.lang.AutoCloseable {

    @Override
    void close();

    // TODO add send

$methods
}
""")

jvpp_impl_template = Template("""
package $base_package.$callback_facade_package;

public final class CallbackJVppFacade implements $base_package.$callback_facade_package.CallbackJVpp {

    private final $base_package.JVpp jvpp;
    private final java.util.Map<Integer, $base_package.$callback_package.JVppCallback> callbacks;

    public CallbackJVppFacade(final $base_package.JVpp jvpp,
                              java.util.Map<Integer, $base_package.$callback_package.JVppCallback> callbacks) {
        if(jvpp == null) {
            throw new java.lang.NullPointerException("jvpp is null");
        }
        this.jvpp = jvpp;
        this.callbacks = callbacks;
    }

    @Override
    public void close() {
    }

    // TODO add send()

$methods
}
""")

method_template = Template(
    """    void $name($base_package.$dto_package.$request request, $base_package.$callback_package.$callback callback);""")
method_impl_template = Template("""    public final void $name($base_package.$dto_package.$request request, $base_package.$callback_package.$callback callback) {
        synchronized (callbacks) {
            callbacks.put(jvpp.$name(request), callback);
        }
    }
""")

no_arg_method_template = Template("""    void $name($base_package.$callback_package.$callback callback);""")
no_arg_method_impl_template = Template("""    public final void $name($base_package.$callback_package.$callback callback) {
        synchronized (callbacks) {
            callbacks.put(jvpp.$name(), callback);
        }
    }
""")


def generate_jvpp(func_list, base_package, dto_package, callback_package, callback_facade_package):
    """ Generates callback facade """
    print "Generating JVpp callback facade"

    if os.path.exists(callback_facade_package):
        util.remove_folder(callback_facade_package)

    os.mkdir(callback_facade_package)

    methods = []
    methods_impl = []
    for func in func_list:

        if util.is_notification(func['name']) or util.is_ignored(func['name']):
            # TODO handle notifications
            continue

        camel_case_name = util.underscore_to_camelcase(func['name'])
        camel_case_name_upper = util.underscore_to_camelcase_upper(func['name'])
        if util.is_reply(camel_case_name):
            continue

        # Strip suffix for dump calls
        callback_type = get_request_name(camel_case_name_upper, func['name']) + callback_gen.callback_suffix

        if len(func['args']) == 0:
            methods.append(no_arg_method_template.substitute(name=camel_case_name,
                                                             base_package=base_package,
                                                             dto_package=dto_package,
                                                             callback_package=callback_package,
                                                             callback=callback_type))
            methods_impl.append(no_arg_method_impl_template.substitute(name=camel_case_name,
                                                                       base_package=base_package,
                                                                       dto_package=dto_package,
                                                                       callback_package=callback_package,
                                                                       callback=callback_type))
        else:
            methods.append(method_template.substitute(name=camel_case_name,
                                                      request=camel_case_name_upper,
                                                      base_package=base_package,
                                                      dto_package=dto_package,
                                                      callback_package=callback_package,
                                                      callback=callback_type))
            methods_impl.append(method_impl_template.substitute(name=camel_case_name,
                                                                request=camel_case_name_upper,
                                                                base_package=base_package,
                                                                dto_package=dto_package,
                                                                callback_package=callback_package,
                                                                callback=callback_type))

    join = os.path.join(callback_facade_package, "CallbackJVpp.java")
    jvpp_file = open(join, 'w')
    jvpp_file.write(
        jvpp_ifc_template.substitute(methods="\n".join(methods),
                                     base_package=base_package,
                                     dto_package=dto_package,
                                     callback_facade_package=callback_facade_package))
    jvpp_file.flush()
    jvpp_file.close()

    jvpp_file = open(os.path.join(callback_facade_package, "CallbackJVppFacade.java"), 'w')
    jvpp_file.write(jvpp_impl_template.substitute(methods="\n".join(methods_impl),
                                                  base_package=base_package,
                                                  dto_package=dto_package,
                                                  callback_package=callback_package,
                                                  callback_facade_package=callback_facade_package))
    jvpp_file.flush()
    jvpp_file.close()

    generate_callback(func_list, base_package, dto_package, callback_package, callback_facade_package)


jvpp_facade_callback_template = Template("""
package $base_package.$callback_facade_package;

/**
 * Async facade callback setting values to future objects
 */
public final class CallbackJVppFacadeCallback implements $base_package.$callback_package.JVppGlobalCallback {

    private final java.util.Map<Integer, $base_package.$callback_package.JVppCallback> requests;

    public CallbackJVppFacadeCallback(final java.util.Map<Integer, $base_package.$callback_package.JVppCallback> requestMap) {
        this.requests = requestMap;
    }

$methods
}
""")

jvpp_facade_callback_method_template = Template("""
    @Override
    @SuppressWarnings("unchecked")
    public void on$callback_dto($base_package.$dto_package.$callback_dto reply) {

        $base_package.$callback_package.$callback callback;
        synchronized(requests) {
            callback = ($base_package.$callback_package.$callback) requests.remove(reply.context);
        }

        if(callback != null) {
            callback.on$callback_dto(reply);
        }
    }
""")


def generate_callback(func_list, base_package, dto_package, callback_package, callback_facade_package):
    callbacks = []
    for func in func_list:

        if util.is_notification(func['name']) or util.is_ignored(func['name']):
            # TODO handle notifications
            continue

        camel_case_name_with_suffix = util.underscore_to_camelcase_upper(func['name'])
        if not util.is_reply(camel_case_name_with_suffix):
            continue

        callbacks.append(jvpp_facade_callback_method_template.substitute(base_package=base_package,
                                                                         dto_package=dto_package,
                                                                         callback_package=callback_package,
                                                                         callback=util.remove_reply_suffix(camel_case_name_with_suffix) + callback_gen.callback_suffix,
                                                                         callback_dto=camel_case_name_with_suffix))

    jvpp_file = open(os.path.join(callback_facade_package, "CallbackJVppFacadeCallback.java"), 'w')
    jvpp_file.write(jvpp_facade_callback_template.substitute(base_package=base_package,
                                                             dto_package=dto_package,
                                                             callback_package=callback_package,
                                                             methods="".join(callbacks),
                                                             callback_facade_package=callback_facade_package))
    jvpp_file.flush()
    jvpp_file.close()


# Returns request name or special one from unconventional_naming_rep_req map
def get_request_name(camel_case_dto_name, func_name):
    if func_name in reverse_dict(util.unconventional_naming_rep_req):
        request_name = util.underscore_to_camelcase_upper(reverse_dict(util.unconventional_naming_rep_req)[func_name])
    else:
        request_name = camel_case_dto_name
    return remove_suffix(request_name)


def reverse_dict(map):
    return dict((v, k) for k, v in map.iteritems())


def remove_suffix(name):
    if util.is_reply(name):
        return util.remove_reply_suffix(name)
    else:
        if util.is_dump(name):
            return util.remove_suffix(name, util.dump_suffix)
        else:
            return name
