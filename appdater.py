"""
appdater

(c) Jakob Rieck 2018

Tool to search for updates for purchased apps and "purchase" newly released free apps.
After appdater runs, appxtractor can be run again to extract information from new apps.
"""

from misc.logger import create_logger
from misc.date_utils import Date
import os.path
import os
import argparse
import jsonlines
import datetime

logger = create_logger('appdater')


def infos_from_itunes_dump(dump_path):
    """Given a Mac App Store dump in jsonlines format (-> mas_crawl_manager), extracts the information
    as a dictionary mapping bundleId to whole entry."""
    assert(os.path.isfile(dump_path))

    result = dict()

    with jsonlines.open(dump_path, mode='r') as reader:
        for obj in reader:
            if "bundleId" not in obj or "version" not in obj or "price" not in obj:
                logger.error("Object does not contain required keys. Skipping.")
                continue

            result[obj["bundleId"]] = obj

    return result


def versions_for_app(app_path):
    """Return versions for an app (see also function directly below)"""
    assert(os.path.isdir(app_path))

    versions = set()

    for potential_version in os.listdir(app_path):
        # Skip invalid entries
        if potential_version.startswith("."):
            continue

        versions.add(potential_version)

    assert(len(versions) != 0)

    return versions


def infos_for_results(result_path):
    """Parses the contents of path (assumed to be the results folder from an invocation of `appxtractor.py`.

    For each bundleId this function extracs the list of available versions for which information has previously
    been saved. The information is returned as a dictionary mapping bundle ids to sets of versions (where the
    entries in the set are strings!)
    """
    infos = dict()

    for app_path in os.listdir(result_path):
        # Skip invalid entries
        if app_path.startswith("."):
            continue

        app_versions = versions_for_app(os.path.join(result_path, app_path))
        infos[app_path] = app_versions

    return infos


def identify_new_apps(result_infos, itunes_infos):
    """Given result_infos and itunes_infos (see functions above), compute the subset of (free) apps that
    are not part of the results.

    These are just the apps where no versions is contained in the results.
    Returns a list of iTunes IDs (to be used by the `mas` tool)"""
    new_apps = list()

    for bundleId in itunes_infos:
        app_info = itunes_infos[bundleId]
        if app_info["price"] == 0.0:
            if bundleId not in result_infos:
                itunes_id = app_info["trackId"]
                new_apps.append(itunes_id)

    return new_apps


def identify_updates_available(result_infos, itunes_infos, updates_since = None):
    """Identify previously purchased apps for which an update is available.
    Return the trackId (used by the `mas` tool) for each app in a list.

    Since the version parameter returned by the iTunes API does not necessarily correspond
    with the latest version per the Info.plist, a more reliable way to filter results is
    to also provide a date `updates_since`, which further filters results. If such a date is
    not specified, the results _will_ contain versions that have already been installed."""

    # List of apps for which an update is available
    updates_avail = list()

    for bundleId in result_infos:
        analysed_versions = result_infos[bundleId]

        if bundleId in itunes_infos:
            itunes_info = itunes_infos[bundleId]
            curr_version = itunes_info["version"]

            if curr_version not in analysed_versions:
                # Further filter by time of release (see above for reasoning!)
                if updates_since and "currentVersionReleaseDate" in itunes_info:
                    version_release_data = datetime.datetime.strptime(itunes_info["currentVersionReleaseDate"],
                                                                      "%Y-%m-%dT%H:%M:%SZ")
                    if version_release_data >= updates_since:
                        updates_avail.append(itunes_info["trackId"])
                else:
                    logger.info("Could not filter by time because either `updates_since` not provided or iTunes dump incomplete.")
                    updates_avail.append(itunes_info["trackId"])
        else:
            logger.info("Locally installed app {} could not be found in the most recent iTunes dump.".format(bundleId))
            continue

    return updates_avail


def main():
    logger.info("appdater starting")

    parser = argparse.ArgumentParser(description='Identify and download updates and new free apps from the Mac App Store.')
    parser.add_argument('--results', required=True,
                        help='Path to directory containing summaries (-> appxtractor) of previously installed apps.')
    parser.add_argument('--itunes-dump', required=True,
                        help='a recent JSONLINES dump of the Mac App Store app catalog.')
    parser.add_argument('--output', required=True,
                        help="Output files (one ending with .new_apps, one with .updates). Will contain every app it on a new line.")
    parser.add_argument('--updates-only', dest='updates_only', default=False, action='store_true',
                        help='Only update / redownload newer versions of already existing / purchased apps.')
    parser.add_argument('--new-only', dest='new_only', default=False, action='store_true',
                        help='Only purchase and download apps that are newly released or newly free.')

    args = parser.parse_args()

    logger.info("App extracts at: {}, itunes dump at : {}, updates_only: {}, new_only: {}".format(
        args.results,
        args.itunes_dump,
        args.updates_only,
        args.new_only)
    )

    local_infos = infos_for_results(args.results)
    itunes_infos = infos_from_itunes_dump(args.itunes_dump)

    new_apps = identify_new_apps(local_infos, itunes_infos)
    apps_to_update = identify_updates_available(local_infos, itunes_infos,
                                                updates_since=Date.today() - 2) # Check for results in the last two days,
                                                                                # to account for incorrect / missing data
                                                                                # in the intermittent dumps

    logger.info("Identified {} new apps and {} updates available.".format(len(new_apps), len(apps_to_update)))

    with open(args.output + ".new_apps", "w") as outfile:
        for app in new_apps:
            outfile.write("{}\n".format(app))

    with open(args.output + ".updates", "w") as outfile:
        for app in apps_to_update:
            outfile.write("{}\n".format(app))


if __name__ == "__main__":
    main()