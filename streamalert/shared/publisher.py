"""
Copyright 2017-present Airbnb, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from abc import abstractmethod
from copy import deepcopy
from inspect import isclass

from streamalert.shared.config import load_config
from streamalert.shared.importer import import_folders
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


class PublisherError(Exception):
    """Exception to raise for any errors with invalid publishers"""


class PublisherRegistrationError(PublisherError):
    """Exception to raise when an error occurs during the @Register step of a publisher"""


class PublisherAssemblyError(PublisherError):
    """Exception to raise when a publisher fails lookup or assembly"""


class Register:
    """This is a decorator used to register publishers into the AlertPublisherRepository."""

    def __new__(cls, class_or_function):
        AlertPublisherRepository.register_publisher(class_or_function)

        return class_or_function  # Return the definition, not the instantiated object


class AlertPublisher:
    """Interface for a Publisher. All class-based publishers must inherit from this class."""

    @abstractmethod
    def publish(self, alert, publication):
        """Publishes the given alert.

        As a general rule of thumb, published fields that are specific to a certain output are
        published as top-level keys of the following format:

        [output service name].[field name]

        E.g. "demisto.blah"

        Args:
            alert (Alert): The alert instance to publish.
            publication (dict): An existing publication generated by previous publishers in the
                series of publishers, or {}.

        Returns:
            dict: The published alert.
        """


class CompositePublisher(AlertPublisher):
    """A publisher class that combines the logic of multiple other publishers together in series

    To reduce the chance that one publisher has side effects in other publishers in the chain,
    we use deepcopy between the publishers.

    Note: This publisher is not meant to be @Register'd as it does not have any logic on its own.
          It is only meant to be composed by AlertPublisherRepository to give a common interface to
          multiple publishers chained in sequence.
    """

    def __init__(self, publishers):
        self._publishers = publishers  # Type list(AlertPublisher)

        for publisher in self._publishers:
            if not isinstance(publisher, AlertPublisher):
                LOGGER.error("CompositePublisher given invalid publisher")

    def publish(self, alert, publication):
        for publisher in self._publishers:
            try:
                publication = deepcopy(publication)
                publication = publisher.publish(alert, publication)
            except KeyError:
                LOGGER.exception(
                    "CompositePublisher encountered KeyError with publisher: %s",
                    publisher.__class__.__name__,
                )
                raise

        return publication


class WrappedFunctionPublisher(AlertPublisher):
    """A class only used to wrap a function publisher."""

    def __init__(self, function):
        self._function = function

    def publish(self, alert, publication):
        return self._function(alert, publication)


class AlertPublisherRepository:
    """A repository mapping names -> publishers

    As a usability optimization, using this Repository will eagerly load and register all
    publishers in the application.
    """

    _publishers = {}
    _is_imported = False

    @classmethod
    def import_publishers(cls):
        if not cls._is_imported:
            config = load_config()
            import_folders(*config["global"]["general"].get("publisher_locations", []))
            cls._is_imported = True

    @staticmethod
    def is_valid_publisher(thing):
        """Returns TRUE if the given reference can be registered as a publisher

        Publishers are valid if and only if they fall into one of the following categories:

        * They are a python function that accepts 2 arguments: (alert: Alert, publication: dict)
        * They are a python class that extends AlertPublisher

        Args:
            thing (mixed): Any primitive or reference to be checked

        Returns:
            bool
        """

        # We have to put the isclass() check BEFORE the callable() check because classes are also
        # callable!
        return issubclass(thing, AlertPublisher) if isclass(thing) else callable(thing)

    @staticmethod
    def get_publisher_name(class_or_function):
        """Given a class or function, will return its fully qualified name.

        This is useful for assigning a unique string name for a publisher.

        Args:
            class_or_function (callable|Class): A reference to a python function or class

        Returns:
            string
        """
        return "{}.{}".format(class_or_function.__module__, class_or_function.__name__)

    @classmethod
    def register_publisher(cls, publisher):
        """Registers the publisher into the repository.

        To standardize the interface of publishers, if a function publisher is given, it will be
        wrapped with a WrappedFunctionPublisher instance prior to being registed into the
        Repository.

        Args:
             publisher (callable|AlertPublisher): An instance of a publisher class or a function
        """
        if not AlertPublisherRepository.is_valid_publisher(publisher):
            error = (
                "Could not register publisher {}; Not callable nor subclass of AlertPublisher"
            ).format(publisher)
            raise PublisherRegistrationError(error)

        if isclass(publisher):
            # If the provided publisher is a Class, then we simply need to instantiate an instance
            # of the class and register it.
            publisher_instance = publisher()
        else:
            # If the provided publisher is a function, we wrap it with a WrappedFunctionPublisher
            # to make them easier to handle.
            publisher_instance = WrappedFunctionPublisher(publisher)

        name = AlertPublisherRepository.get_publisher_name(publisher)

        if name in cls._publishers:
            error = "Publisher with name [{}] has already been registered.".format(name)
            raise PublisherRegistrationError(error)

        cls._publishers[name] = publisher_instance

    @classmethod
    def get_publisher(cls, name):
        """Returns the publisher with the given name

        Args:
            name (str): The name of the publisher.

        Returns:
            AlertPublisher|None
        """
        if cls.has_publisher(name):
            return cls._publishers[name]

        LOGGER.error("Publisher [%s] does not exist", name)

    @classmethod
    def has_publisher(cls, name):
        """Returns true if the given publisher name has been registered in this Repository"""
        cls.import_publishers()
        return name in cls._publishers

    @classmethod
    def all_publishers(cls):
        """Returns all registered publishers in a dict mapping their unique name to instances.

        Remember: Function publishers are wrapped with WrappedFunctionPublisher
        Also remember: These publishers are INSTANCES of the publisher classes, not the classes
            themselves.

        Returns:
            dict
        """
        return cls._publishers

    @classmethod
    def create_composite_publisher(cls, publisher_names):
        """Assembles a single publisher that combines logic from multiple publishers

        Args:
            publisher_names (list(str)): A list of string names of publishers

        Return:
            CompositePublisher|DefaultPublisher
        """
        publisher_names = publisher_names or []
        publishers = []

        for publisher_name in publisher_names:
            publisher = cls.get_publisher(publisher_name)
            if publisher:
                publishers.append(publisher)

        if not publishers:
            # If no publishers were given, or if all of the publishers failed to load, then we
            # load a default publisher.
            default_publisher_name = cls.get_publisher_name(DefaultPublisher)
            return cls.get_publisher(default_publisher_name)

        return CompositePublisher(publishers)


@Register
class DefaultPublisher(AlertPublisher):
    """The default publisher that is used when no other publishers are provided"""

    def publish(self, alert, publication):
        return alert.output_dict()
